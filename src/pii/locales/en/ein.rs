//! US Employer Identification Number (EIN): validator + detection rule.
//!
//! Official sources (retrieved 2026-10-30):
//!
//! 1. IRS Publication 1635 (Rev. 2-2014), "Understanding Your EIN",
//!    section "What is an EIN?"
//!    (<https://www.irs.gov/pub/irs-pdf/p1635.pdf>): "An Employer
//!    Identification Number (EIN) is a nine-digit number that IRS assigns
//!    in the following format: XX-XXXXXXX."
//! 2. IRS web page "Valid EINs" (page last reviewed 09-Apr-2026), table
//!    "IRS campus or other location / Valid EIN prefixes"
//!    (<https://www.irs.gov/businesses/small-businesses-self-employed/valid-eins>):
//!    "The first two digits of your EIN show the IRS campus that assigned
//!    it or if you applied online." The table lists Andover 10, 12;
//!    Atlanta 60, 67; Austin 50, 53; Brookhaven 01-06, 11, 13, 14, 16, 21,
//!    22, 23, 25, 34, 51, 52, 54-59, 65; Cincinnati 30, 32, 35-38, 61;
//!    Fresno 15, 24; Kansas City 40, 44; Memphis 94, 95; Ogden 80, 90;
//!    Philadelphia 33, 39, 41-43, 46, 48, 62-64, 66, 68, 71-77, 85-88,
//!    91-93, 98, 99; Internet 20, 26, 27, 33, 39, 41, 42, 45-47, 81-88, 92,
//!    93, 99; Small Business Administration 31. Their union (83 prefixes)
//!    is `VALID_PREFIXES`.
//!
//! Only the hyphenated IRS form is claimed: a bare 9-digit run is never an
//! EIN here (the IRS format carries the hyphen; SSN precedent).
//!
//! Format only: no check digit exists, so a cue is REQUIRED and the score
//! is 0.9. A bare "ein" is not a cue (substring of "being", "protein"), and
//! neither are its one-sided forms: "ein " also ends "protein", "Stein",
//! "mein", "nein", "kein", " ein" also starts the German "eine", "einen",
//! "einem", "einer". The cues are the delimited label forms ("EIN:",
//! "EIN#", "(EIN)", " EIN " inside a line, "FEIN ", "FEIN:", "FEIN#") and the spelled-out
//! names; a bare "tin" is never used (substring of "routing", "meeting").
//! A line that starts "EIN 12-..." without a colon is therefore not
//! claimed (a cue cannot be delimited before the start of a line).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, two_digits, ContextPolicy, Rule};

/// Cue words that make an EIN candidate claimable. "FEIN" needs its own
/// forms: the short "ein:" / "ein#" cues count only at a word start
/// (`context` module doc), and inside "FEIN:" the "ein" follows an "f".
pub(super) const CUES: &[&str] = &[
    "ein:",
    "ein#",
    "(ein)",
    " ein ",
    "fein ",
    "fein:",
    "fein#",
    "employer id",
    "federal tax id",
    "tax id number",
];

/// The union of the IRS "Valid EINs" prefix table, as inclusive ranges.
const VALID_PREFIXES: &[(u32, u32)] = &[
    (1, 6),
    (10, 16),
    (20, 27),
    (30, 39),
    (40, 48),
    (50, 59),
    (60, 68),
    (71, 77),
    (80, 88),
    (90, 95),
    (98, 99),
];

/// Returns `true` if `s` is a US Employer Identification Number in the
/// IRS format `XX-XXXXXXX` whose two-digit prefix appears in the IRS
/// "Valid EINs" table.
///
/// # Examples
/// ```
/// use redactify::valid_us_ein;
/// assert!(valid_us_ein("10-1234567")); // prefix 10 = Andover campus
/// assert!(!valid_us_ein("07-1234567")); // 07 is not a valid prefix
/// assert!(!valid_us_ein("101234567")); // the IRS format carries the hyphen
/// ```
#[must_use]
pub fn valid_us_ein(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[2] != b'-' {
        return false;
    }
    if !b[..2].iter().chain(&b[3..]).all(u8::is_ascii_digit) {
        return false;
    }
    let prefix = two_digits(&b[..2]);
    VALID_PREFIXES
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&prefix))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsEin,
        r"(?<![0-9-])\d{2}-\d{7}(?![0-9-])",
        Some(valid_us_ein),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_us_ein, VALID_PREFIXES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn prefix_table() {
        let count: u32 = VALID_PREFIXES.iter().map(|&(lo, hi)| hi - lo + 1).sum();
        assert_eq!(count, 83);
        for bad in [
            0, 7, 8, 9, 17, 18, 19, 28, 29, 49, 69, 70, 78, 79, 89, 96, 97,
        ] {
            assert!(!valid_us_ein(&format!("{bad:02}-1234567")), "{bad:02}");
        }
        for good in [1, 10, 12, 20, 31, 47, 65, 77, 88, 95, 98, 99] {
            assert!(valid_us_ein(&format!("{good:02}-1234567")), "{good:02}");
        }
    }

    #[test]
    fn format_edges() {
        assert!(valid_us_ein("31-0000001"));
        assert!(!valid_us_ein("101234567"));
        assert!(!valid_us_ein("10 1234567"));
        assert!(!valid_us_ein("10-123456"));
        assert!(!valid_us_ein("10-12345678"));
        assert!(!valid_us_ein("1A-1234567"));
        assert!(!valid_us_ein(""));
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["en"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(kinds("EIN: 10-1234567"), vec![EntityType::UsEin]);
        assert_eq!(kinds("FEIN 10-1234567"), vec![EntityType::UsEin]);
        // the colon / hash label forms (the "ein:" cue cannot start inside
        // "fein:", word-start rule)
        assert_eq!(kinds("FEIN: 10-1234567"), vec![EntityType::UsEin]);
        assert_eq!(kinds("FEIN#10-1234567"), vec![EntityType::UsEin]);
        assert_eq!(kinds("Employer FEIN:10-1234567"), vec![EntityType::UsEin]);
        // ...still at a word start only
        assert!(kinds("Carfein: 10-1234567").is_empty());
        assert_eq!(kinds("federal tax id 10-1234567"), vec![EntityType::UsEin]);
        assert!(kinds("lot 10-1234567 shipped").is_empty());
        assert!(kinds("protein10-1234567").is_empty());
        assert!(kinds("being 10-1234567").is_empty());
    }
}
