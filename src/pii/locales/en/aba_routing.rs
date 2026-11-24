//! US ABA routing transit number (RTN): validator + detection rule.
//!
//! Official sources (retrieved 2026-10-30):
//!
//! 1. IRS Publication 1346 (Rev. 10-2012), "Electronic Return File
//!    Specifications and Record Layouts for Individual Income Tax
//!    Returns", Part 1, Section 6, .03 "Optional Validation of Routing
//!    Transit Number (RTN)" and record check 0019
//!    (<https://www.irs.gov/pub/irs-pdf/p1346.pdf>): "Multiply each of
//!    the first eight digits of the RTN by the appropriate multiplier
//!    (the first digit multiplied by 3, the second by 7, the third by 1,
//!    the fourth by 3, the fifth by 7, the sixth by 1, the seventh by 3,
//!    and the eighth by 7). [...] Subtract the sum of all the products
//!    from the next multiple of ten. [...] The remainder is the check
//!    digit, which must be equal to the ninth digit of the RTN." Worked
//!    example: `120139013`. "Routing Transit Number (RTN) (SEQ 1272) must
//!    contain nine numeric characters. The first two positions must be 01
//!    through 12, or 21 through 32".
//! 2. 12 CFR Part 229 (Regulation CC), Appendix A, "Routing Number Guide
//!    to Next-Day Availability Checks and Local Checks"
//!    (<https://www.ecfr.gov/current/title-12/chapter-II/subchapter-A/part-229/appendix-Appendix%20A%20to%20Part%20229>):
//!    "The routing number takes two forms: a fractional form and a
//!    nine-digit form. [...] the first two digits of the routing number
//!    identify the Federal Reserve District [...] Adding 2 to the first
//!    digit denotes a thrift institution." Its tables print the
//!    nine-digit form in 4-4-1 groups (`0110 0001 5`); all 67 numbers
//!    listed there pass this validator.
//! 3. IRS 1040 (and 1040-SR) Instructions, Tax Year 2025, Line 35b
//!    (<https://www.irs.gov/pub/irs-pdf/i1040gi.pdf>): "The routing
//!    number must be nine digits. The first two digits must be 01 through
//!    12 or 21 through 32." Its sample-check number `250250025` is an
//!    illustration that fails the check digit; the validator follows the
//!    algorithm, not the illustration.
//!
//! Accepted spellings: nine contiguous digits (the MICR line) and the 4-4-1
//! grouping of the Regulation CC tables. Other prefixes (`00`, `61`-`72`,
//! `80`) appear in no retrieved official source and are not claimed.
//!
//! Cue REQUIRED (score 1.0, checksum verified): the prefix range plus the
//! single check digit still admit about 2.4% of random 9-digit runs
//! (measured on 200,000 samples). A bare "aba" is not a cue (substring of
//! "database", "abacus"), nor a bare "rtn" (substring of "partner").

use crate::pii::entity::EntityType;
use crate::pii::locales::{code_chars, rule, two_digits, ContextPolicy, Rule};

/// Cue words that make a routing-number candidate claimable.
pub(super) const CUES: &[&str] = &[
    "routing",
    "aba:",
    "aba#",
    "aba number",
    "rtn:",
    "rtn#",
    "rtn ",
    " rtn",
    "transit number",
];

/// Returns `true` if `s` is a valid US ABA routing transit number: nine
/// ASCII digits, contiguous or in the 4-4-1 grouping (`0110 0001 5`), whose
/// first two digits are 01-12 or 21-32 and whose 3-7-1 weighted digit sum
/// is a multiple of 10 (IRS Publication 1346).
///
/// # Examples
/// ```
/// use redactify::valid_us_aba_routing;
/// assert!(valid_us_aba_routing("120139013")); // IRS Pub 1346 example
/// assert!(valid_us_aba_routing("0110 0001 5")); // 12 CFR 229 App. A
/// assert!(!valid_us_aba_routing("250250025")); // IRS sample check: check digit off
/// assert!(!valid_us_aba_routing("410000001")); // prefix 41 outside 01-12 / 21-32
/// ```
#[must_use]
pub fn valid_us_aba_routing(s: &str) -> bool {
    let b = s.as_bytes();
    let grouped = b.len() == 11 && b[4] == b' ' && b[9] == b' ';
    if !(b.len() == 9 || grouped) {
        return false;
    }
    let Some(d) = code_chars::<9>(s, u8::is_ascii_digit, b" ") else {
        return false;
    };
    let prefix = two_digits(&d[..2]);
    if !matches!(prefix, 1..=12 | 21..=32) {
        return false;
    }
    const WEIGHTS: [u32; 9] = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = d
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    sum % 10 == 0
}

/// The pattern consumes the first digit before its lookbehind and leaves
/// the 01-12 / 21-32 prefix to the validator: every start position then
/// fails in one backtracking step, so a very long line (a 200,000-mark
/// combining run) stays within the engine's backtrack budget. A prefix
/// alternation ahead of the lookbehind measurably exhausted it there.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsAbaRouting,
        r"[0-3](?<!\d[0-3])\d{3} ?\d{4} ?\d(?!\d)",
        Some(valid_us_aba_routing),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_us_aba_routing;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn official_vectors() {
        // IRS Pub 1346 worked example and Regulation CC table entries
        for v in ["120139013", "0110 0001 5", "1210 0037 4", "011000015"] {
            assert!(valid_us_aba_routing(v), "{v}");
        }
        // IRS 1040 sample-check illustration: prefix fine, weighted sum 101
        assert!(!valid_us_aba_routing("250250025"));
        // independent recomputation of the Pub 1346 example: 3*1 + 7*2 +
        // 1*0 + 3*1 + 7*3 + 1*9 + 3*0 + 7*1 = 57 -> check digit 3
        assert_eq!(3 + 7 * 2 + 3 + 7 * 3 + 9 + 7, 57);
    }

    #[test]
    fn prefix_and_form_edges() {
        assert!(!valid_us_aba_routing("120139014")); // check digit off
        assert!(!valid_us_aba_routing("410000001")); // passes 3-7-1, prefix 41
        assert!(!valid_us_aba_routing("610000005")); // 6x not in the sources
        assert!(!valid_us_aba_routing("800000006")); // 8x not in the sources
        assert!(!valid_us_aba_routing("000000000")); // prefix 00
        assert!(!valid_us_aba_routing("0110-0001-5")); // hyphens are not a form
        assert!(!valid_us_aba_routing("0110 00015")); // only the 4-4-1 grouping
        assert!(!valid_us_aba_routing("12013901")); // 8 digits
        assert!(!valid_us_aba_routing(""));
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["en"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(
            kinds("routing number 120139013"),
            vec![EntityType::UsAbaRouting]
        );
        assert_eq!(kinds("RTN: 0110 0001 5"), vec![EntityType::UsAbaRouting]);
        assert!(kinds("order 120139013 shipped").is_empty());
        // substring traps stay silent
        assert!(kinds("database 120139013").is_empty());
        assert!(kinds("partner 120139013").is_empty());
    }
}
