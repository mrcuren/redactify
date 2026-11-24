//! UK (GB) driving licence driver number: validator + detection rule.
//!
//! Official source (retrieved 2026-10-30): DVLA leaflet INS57P
//! "Information on driving licences" (cover dated 7/25), section "How to
//! check your driver number"
//! (<https://assets.publishing.service.gov.uk/government/uploads/system/uploads/attachment_data/file/775657/ins57p-info-driving-licences.pdf>):
//! "MORGA 657054 SM 9IJ ** A. This is the first 5 letters of your surname.
//! If your surname has fewer than 5 letters, the remaining spaces will be
//! made up using the number 9 (for example, MAN99). B. The first and last
//! numbers are the year of birth. The second and third numbers are the
//! month of birth. (If you are a female, '5' is added to the second number
//! [...] a woman born in October the second and third numbers would be
//! 60.) The fourth and fifth digits show the day of your birth. C. The
//! first 2 initials of your first names. If you have only one initial then
//! the second character will be a '9'. D. Computer check digits randomly
//! generated as a secure measure. E. This is the licence issue number
//! [...] This is not part of the driver number."
//!
//! The 16-character driver number is therefore: 5 surname characters
//! (letters, padded with trailing 9s), 6 digits (decade digit, month with
//! +50 for women, day, year digit), 2 initials (a single initial padded
//! with 9) and 3 computer check characters. The validator checks the
//! surname padding, the month and the calendar day (the century is not
//! encoded, so 29 February is accepted when the two-digit year is a leap
//! year in some century). The check characters are "randomly generated":
//! no algorithm exists, so they are only required to be letters or
//! digits. The printed form groups the number as 5/6/2/3 with single
//! spaces (`MORGA 657054 SM 9IJ`); each group space is optional. The issue
//! number (E) is not part of the driver number and is not claimed.
//! Northern Ireland licences use a different numbering (out of scope: no
//! official source retrieved).
//!
//! Format only: a cue is REQUIRED and the score is 0.9.

use crate::pii::entity::EntityType;
use crate::pii::locales::{
    days_in_month, is_leap_two_digit_year, rule, two_digits, ContextPolicy, Rule,
};

/// Cue words that make a driver-number candidate claimable.
pub(super) const CUES: &[&str] = &[
    "driving licence",
    "driving license",
    "driver number",
    "driver's licence",
    "licence number",
    "license number",
    "dvla",
];

/// The 16 driver-number characters of `s` (groups 5/6/2/3, each group
/// optionally preceded by one space), or `None`.
fn driver_number(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let (mut i, mut n) = (0usize, 0usize);
    for (k, len) in [5usize, 6, 2, 3].into_iter().enumerate() {
        if k > 0 && b.get(i) == Some(&b' ') {
            i += 1;
        }
        let part = b.get(i..i + len)?;
        out[n..n + len].copy_from_slice(part);
        i += len;
        n += len;
    }
    (i == b.len()).then_some(out)
}

/// Returns `true` if `s` has the structure of a GB driving licence driver
/// number (DVLA INS57P): surname letters padded with trailing `9`s, a
/// valid encoded birth date (month + 50 for women), one or two initials
/// (`9` padding) and three check characters; spaces between the 5/6/2/3
/// groups are optional.
///
/// # Examples
/// ```
/// use redactify::valid_uk_driving_licence;
/// assert!(valid_uk_driving_licence("MORGA 657054 SM 9IJ")); // DVLA INS57P
/// assert!(valid_uk_driving_licence("MORGA657054SM9IJ"));
/// assert!(!valid_uk_driving_licence("MORGA613054SM9IJ")); // month 13
/// assert!(!valid_uk_driving_licence("MO9GA657054SM9IJ")); // padding not at the end
/// ```
#[must_use]
pub fn valid_uk_driving_licence(s: &str) -> bool {
    let Some(c) = driver_number(s) else {
        return false;
    };
    // surname: letters, then only 9s (at least one letter)
    let pad = c[..5].iter().position(|&x| x == b'9').unwrap_or(5);
    if pad == 0
        || !c[..pad].iter().all(u8::is_ascii_uppercase)
        || !c[pad..5].iter().all(|&x| x == b'9')
    {
        return false;
    }
    if !c[5..11].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let coded_month = two_digits(&c[6..8]);
    let month = if coded_month > 50 {
        coded_month - 50
    } else {
        coded_month
    };
    if !(1..=12).contains(&month) {
        return false;
    }
    let day = two_digits(&c[8..10]);
    let yy = u32::from(c[5] - b'0') * 10 + u32::from(c[10] - b'0');
    if day == 0 || day > days_in_month(month, is_leap_two_digit_year(yy)) {
        return false;
    }
    c[11].is_ascii_uppercase()
        && (c[12].is_ascii_uppercase() || c[12] == b'9')
        && c[13..]
            .iter()
            .all(|x| x.is_ascii_uppercase() || x.is_ascii_digit())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UkDrivingLicence,
        r"(?<![A-Za-z0-9])[A-Z][A-Z9]{4} ?[0-9](?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9] ?[A-Z][A-Z9] ?[A-Z0-9]{3}(?![A-Za-z0-9])",
        Some(valid_uk_driving_licence),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_uk_driving_licence as ok;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn official_example_and_structure_edges() {
        assert!(ok("MORGA 657054 SM 9IJ"));
        assert!(ok("MORGA657054SM9IJ"));
        assert!(ok("MAN99657054SM9IJ")); // INS57P padding example
        assert!(ok("MORGA610054S99IJ")); // male, October, single initial
        assert!(ok("MORGA602290SM9IJ")); // 29 February 1960 (leap)
        assert!(!ok("MORGA602291SM9IJ")); // 29 February 1961
        assert!(!ok("MORGA613054SM9IJ")); // month 13
        assert!(!ok("MORGA650054SM9IJ")); // month 50 + 0
        assert!(!ok("MORGA657354SM9IJ")); // day 35
        assert!(!ok("MORGA657004SM9IJ")); // day 00
        assert!(!ok("MO9GA657054SM9IJ")); // padding not at the end
        assert!(!ok("9ORGA657054SM9IJ")); // no surname letter
        assert!(!ok("MORGA6570549M9IJ")); // padding in the first initial
        assert!(!ok("MORGA  657054SM9IJ")); // two spaces
        assert!(!ok("morga657054sm9ij")); // lowercase
        assert!(!ok("MORGA657054SM9I")); // 15 characters
        assert!(!ok(""));
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["uk"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(
            kinds("driving licence MORGA 657054 SM 9IJ"),
            vec![EntityType::UkDrivingLicence]
        );
        assert_eq!(
            kinds("DVLA: MORGA657054SM9IJ 35"),
            vec![EntityType::UkDrivingLicence]
        );
        assert!(kinds("ref MORGA657054SM9IJ filed").is_empty());
    }
}
