//! South African company registration number: validator + rule. Format
//! only - no check digit.
//!
//! Official sources:
//!
//! 1. Department of Trade and Industry, Registrar of Companies and of
//!    Close Corporations, Notice No. 1762 of 1999 (Acts Online
//!    republication), <https://www.acts.co.za/companies-act-1973/notices_2_new_numbers.php>,
//!    Schedule paragraphs 2, 4 and 5 (retrieved 2026-10-30): "The office
//!    will from 1 January 2000 issue numbers to all newly incorporated
//!    companies and close corporations using a numbering system that
//!    complies with the following criteria: YYYY/NNNNNN/NN. The first
//!    portion (YYYY) of the number will reflect the year (in full) in
//!    which incorporation was affected. The middle portion (NNNNNN) is a
//!    unique consequential number containing six digits ... The last
//!    portion (NN) is a numeric value indicating the type of enterprise
//!    ... Thus the first private company incorporated on 2 January 2000
//!    will reflect the following registration number: 2000/000001/07." /
//!    "For example an existing registration number 99/12345/07 will change
//!    to 1999/012345/07." / "From 1 January 2001 the use of the newly
//!    allocated registration number will be compulsory."
//! 2. South African Revenue Service, Business Requirements Specification
//!    "SARS_External BRS_2013_IT3s v1.0.0" (20 September 2013, "Official
//!    Publication", archived),
//!    <https://www.sars.gov.za/wp-content/uploads/Docs/3rdParty/Archive/Archived-Business-Requirement-Specification-IT3s-Data-Submission-WATERMARK.pdf>,
//!    7.12 Appendix K "Company registration number validation" (retrieved
//!    2026-10-30): "CCYY/NNNNNN/NN, where the CCYY must be validated to be
//!    from 1800 and up and including the current calendar year. The last
//!    two digits of this number must be validated to be either of the
//!    following: 06, 07, 08, 09, 10, 11, 20, 21, 22, 23, 24, 25, 26, 30,
//!    31".
//!
//! The validator checks the `YYYY/NNNNNN/NN` structure, a year from 1800
//! (SARS) to 2099 (a fixed upper bound standing in for "the current
//! calendar year": the engine reads no clock; CN precedent) and the
//! enterprise-type suffix list of Appendix K. Letter-prefixed numbers are
//! not covered (no official notice defining them was found).
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). Priority tier 7 (national-ID tier); the two `/`
//! separators keep the shape apart from every other rule.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (label forms used for the registration number).
pub(super) const CUES: &[&str] = &[
    "registration no",
    "reg no",
    "reg. no",
    "company reg",
    "cipc",
    "enterprise no",
    "close corporation",
];

/// Enterprise-type suffixes accepted by SARS (IT3s BRS Appendix K).
const TYPE_SUFFIXES: [&[u8; 2]; 15] = [
    b"06", b"07", b"08", b"09", b"10", b"11", b"20", b"21", b"22", b"23", b"24", b"25", b"26",
    b"30", b"31",
];

/// Returns `true` if `number` is a structurally valid South African
/// company registration number: `YYYY/NNNNNN/NN` with a year from 1800 to
/// 2099 and an enterprise-type suffix accepted by SARS (06-11, 20-26, 30,
/// 31). There is no check digit.
///
/// # Examples
/// ```
/// use redactify::valid_za_company_registration;
/// assert!(valid_za_company_registration("2000/000001/07")); // Notice 1762
/// assert!(valid_za_company_registration("1999/012345/07")); // Notice 1762
/// assert!(!valid_za_company_registration("2000/000001/05")); // suffix
/// assert!(!valid_za_company_registration("1799/000001/07")); // year
/// ```
#[must_use]
pub fn valid_za_company_registration(number: &str) -> bool {
    let b = number.as_bytes();
    if b.len() != 14 || b[4] != b'/' || b[11] != b'/' {
        return false;
    }
    let digits = |r: &[u8]| r.iter().all(u8::is_ascii_digit);
    if !digits(&b[..4]) || !digits(&b[5..11]) || !digits(&b[12..]) {
        return false;
    }
    let year = b[..4]
        .iter()
        .fold(0u32, |n, &c| n * 10 + u32::from(c - b'0'));
    (1800..=2099).contains(&year) && TYPE_SUFFIXES.iter().any(|s| s[..] == b[12..])
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ZaCompanyRegistration,
        r"(?<![\d/])(?:18|19|20)\d{2}/\d{6}/\d{2}(?![\d/])",
        Some(valid_za_company_registration),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_za_company_registration;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure_year_and_suffix() {
        for v in [
            "2000/000001/07",
            "1999/012345/07",
            "1800/123456/06",
            "2099/999999/31",
            "2015/123456/23",
        ] {
            assert!(valid_za_company_registration(v), "{v}");
        }
        for v in [
            "2000/000001/05", // suffix not listed
            "2000/000001/12", // suffix not listed
            "1799/000001/07", // before 1800
            "2100/000001/07", // after the bound
            "2000/00001/07",  // five-digit serial
            "99/12345/07",    // pre-2000 short form
            "2000-000001-07", // foreign separator
            "2000/000001/7",  // one-digit suffix
        ] {
            assert!(!valid_za_company_registration(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("file 2000/000001/07 archived", &["za"]).is_empty());
        let ents = engine_detect("CIPC reg no 2000/000001/07", &["za"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::ZaCompanyRegistration);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
    }
}
