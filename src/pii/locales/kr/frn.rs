//! South Korean foreigner registration number (외국인등록번호, FRN):
//! validator + rule. Birth-date and gender-digit validation only - no
//! check digit.
//!
//! Official source: National Tax Service, "Republic of Korea -
//! Information on Tax Identification Numbers" (country sheet published on
//! the OECD AEOI portal, "Last update 30, May, 2023"),
//! <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/korea-tin.pdf>,
//! Section II "TIN Structure" (retrieved 2026-10-30): the registration
//! number "consists of 13 digits (XXXXXX-XXXXXXX)", the first six digits
//! are the date of birth ("a person born on Januay 2, 1985 has the first
//! six digit such as 850102") and the seventh identifies the sex, per the
//! table (read from the text layer): "Koreans: before 2000 Male 1 Female
//! 2; after 2000 Male 3 Female 4; Foreigners: before 2000 Male 5 Female 6;
//! after 2000 Male 7 Female 8".
//!
//! The validator checks the 13-digit shape (`YYMMDD-GNNNNNN` or
//! unseparated), a gender digit `G` of 5-8 (5/6 born before 2000, 7/8
//! from 2000) and a real calendar date in that century. No check digit:
//! no official source publishes one.
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum).
//!
//! Priority: tier 0, for the same reason as the RRN (`kr::rrn`): a
//! Luhn-passing 13-digit value would otherwise be relabeled by the
//! cue-less card rule, and the `kr` pack is registered before `za`.

use super::valid_registration;
use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (the identifier's Korean and English names).
pub(super) const CUES: &[&str] = &[
    "외국인등록번호",
    "외국인번호",
    "외국인 등록",
    "alien reg",
    "foreigner reg",
    "frn",
];

/// Birth century of an FRN gender digit (NTS table, foreigners).
fn century(g: u8) -> Option<u32> {
    match g {
        b'5' | b'6' => Some(1900),
        b'7' | b'8' => Some(2000),
        _ => None,
    }
}

/// Returns `true` if `frn` is a structurally valid South Korean foreigner
/// registration number: 13 digits written `YYMMDD-GNNNNNN` or
/// `YYMMDDGNNNNNN`, gender digit `G` 5-8 (5/6: born 1900-1999, 7/8: born
/// 2000-2099) and a real calendar birth date. There is no check digit.
///
/// # Examples
/// ```
/// use redactify::valid_kr_frn;
/// assert!(valid_kr_frn("850102-5123456"));
/// assert!(valid_kr_frn("0402297123456")); // 29 Feb 2004
/// assert!(!valid_kr_frn("850230-5123456")); // 30 February
/// assert!(!valid_kr_frn("850102-1123456")); // 1 is a Korean (RRN) digit
/// ```
#[must_use]
pub fn valid_kr_frn(frn: &str) -> bool {
    valid_registration(frn, century)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::KrFrn,
        r"(?<![\d-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[5-8]\d{6}(?![\d-])",
        Some(valid_kr_frn),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_kr_frn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn gender_digit_and_date() {
        for v in [
            "850102-5123456",
            "850102-6123456",
            "000101-7123456",
            "000229-8123456", // 2000 is a leap year
            "8501025123456",
        ] {
            assert!(valid_kr_frn(v), "{v}");
        }
        for v in [
            "850230-5123456", // 30 February
            "851302-5123456", // month 13
            "850102-9123456", // gender digit 9 is not in the table
            "850102-4123456", // Korean (RRN) digit
            "000229-5123456", // 29 Feb 1900 does not exist
            "850102-512345",  // 12 digits
        ] {
            assert!(!valid_kr_frn(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("order 850102-5123456 shipped", &["kr"]).is_empty());
        let ents = engine_detect("외국인등록번호: 850102-5123456", &["kr"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::KrFrn);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
    }
}
