//! South African income tax reference number: validator + rule.
//!
//! Official sources:
//!
//! 1. South African Revenue Service, PAYE Employer Reconciliation BRS
//!    V21.2 (Oct-22, "Official Publication"),
//!    <https://www.sars.gov.za/sars_paye_brs-paye-employer-reconciliation_v21-2>
//!    (retrieved 2026-10-30). Appendix B 8.1 "Modulus 10 check on Income
//!    Tax Number": "The last character is a check digit, calculated by
//!    applying the following algorithm: Digit 1 Multiply by 2 (Add result
//!    to total) ... Digit 2 Add to total ... Digit 9 Multiply by 2 ...
//!    When the result of the line item calculation exceeds 9, add the
//!    individual digits together to obtain a single digit result (e.g. 18
//!    = 1+ 8 = 9) ... If the last digit of Total > 0 Then The Check Digit
//!    should be equal to the result of 10 - (the last digit of the Total).
//!    If the last digit of Total = 0 Then The Check Digit should be equal
//!    to zero. Example 1: Tax Reference Number = 0001339050 ... Example 2:
//!    Tax Reference Number = 0667056642". Field 3100 "Income tax reference
//!    number": "the number must only start with either 0, 1, 2, or 3 ...
//!    Where the certificate is issued for Nature of Person E, G, H the
//!    number must start with a 9 ... Must pass modulus 10 test".
//! 2. SARS, "South Africa - Information on Tax Identification Numbers"
//!    (country sheet published on the OECD AEOI portal, 2020),
//!    <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/south-africa-tin.pdf>,
//!    Section II (retrieved 2026-10-30): "A South African Income Tax
//!    reference number is 10 numeric digits long. The tax reference number
//!    can only start with 0, 1, 2, 3 or 9".
//!
//! The 8.1 computation doubles digits 1, 3, 5, 7 and 9 (the odd positions
//! of a 10-digit number, i.e. every second digit from the right starting
//! with the second) and reduces a two-digit product to its digit sum,
//! which is the Luhn check ([`luhn_valid`]); both SARS examples pass it.
//! The validator checks 10 digits, a first digit 0, 1, 2, 3 or 9 and the
//! check digit.
//!
//! Cue policy: a cue is REQUIRED although the number is checksummed (a
//! single check digit admits ~10% of random 10-digit runs; AU TFN / NL
//! BSN precedent), score 1.0 (checksum verified).
//!
//! Priority: tier 3 (checksum beats structural; UK_NHS / DK_CPR
//! precedent). The bare 10-digit shape and the cue "tax reference" are
//! shared with the format-only UK UTR rule, so with both packs enabled a
//! Luhn-valid SARS number keeps its own label. The run must not touch an
//! ASCII letter, so the rule never cuts the digits out of a longer
//! alphanumeric token (a `K`-prefixed UTR, a VAT number with a country
//! prefix) that a lower tier would claim whole.

use crate::pii::entity::EntityType;
use crate::pii::locales::{luhn_valid, rule, ContextPolicy, Rule};

/// Cue words (the reference number's names in SARS documents).
pub(super) const CUES: &[&str] = &[
    "tax ref",
    "tax number",
    "tax no",
    "income tax",
    "sars",
    "itr12",
];

/// Returns `true` if `reference` is a valid South African income tax
/// reference number: 10 digits, first digit 0, 1, 2, 3 or 9, and a valid
/// SARS modulus 10 (Luhn) check digit.
///
/// # Examples
/// ```
/// use redactify::valid_za_tax_reference;
/// assert!(valid_za_tax_reference("0001339050")); // SARS BRS example 1
/// assert!(valid_za_tax_reference("0667056642")); // SARS BRS example 2
/// assert!(!valid_za_tax_reference("0001339051")); // check digit off
/// assert!(!valid_za_tax_reference("4001339052")); // first digit 4
/// ```
#[must_use]
pub fn valid_za_tax_reference(reference: &str) -> bool {
    let b = reference.as_bytes();
    b.len() == 10
        && b.iter().all(u8::is_ascii_digit)
        && matches!(b[0], b'0'..=b'3' | b'9')
        && luhn_valid(b)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ZaTaxReference,
        r"(?<![0-9A-Za-z\-])[01239]\d{9}(?![0-9A-Za-z\-])",
        Some(valid_za_tax_reference),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_za_tax_reference;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    /// The SARS BRS 8.1 table, transcribed literally (digits 1, 3, 5, 7, 9
    /// doubled with a two-digit result reduced to its digit sum).
    fn sars_modulus_10(n: &str) -> bool {
        let d: Vec<u32> = n.bytes().map(|b| u32::from(b - b'0')).collect();
        let total: u32 = d
            .iter()
            .take(9)
            .enumerate()
            .map(|(i, &x)| {
                if i % 2 == 0 {
                    let y = x * 2;
                    y / 10 + y % 10
                } else {
                    x
                }
            })
            .sum();
        let check = if total % 10 > 0 { 10 - total % 10 } else { 0 };
        check == d[9]
    }

    #[test]
    fn sars_table_equals_luhn() {
        assert!(sars_modulus_10("0001339050") && sars_modulus_10("0667056642"));
        let mut x: u64 = 12_345;
        for _ in 0..20_000 {
            x = x
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493)
                % 10_000_000_000;
            let s = format!("{x:010}");
            let luhn = crate::pii::locales::luhn_valid(s.as_bytes());
            assert_eq!(sars_modulus_10(&s), luhn, "{s}");
        }
    }

    #[test]
    fn prefix_and_check_digit() {
        for v in ["0001339050", "0667056642"] {
            assert!(valid_za_tax_reference(v), "{v}");
        }
        for v in [
            "0001339051",  // check digit
            "0667056641",  // check digit
            "4001339052",  // Luhn passes, first digit 4
            "7230767891",  // SARS PAYE reference example, first digit 7
            "000133905",   // 9 digits
            "00013390500", // 11 digits
        ] {
            assert!(!valid_za_tax_reference(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required_and_letters_bound_the_run() {
        assert!(engine_detect("batch 0001339050 shipped", &["za"]).is_empty());
        let ents = engine_detect("SARS tax reference 0001339050", &["za"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::ZaTaxReference);
        assert!((ents[0].score - 1.0).abs() < f32::EPSILON);
        assert!(engine_detect("tax ref K0001339050", &["za"]).is_empty());
    }
}
