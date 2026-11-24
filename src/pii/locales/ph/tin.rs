//! Philippine Taxpayer Identification Number (TIN): validator + rules.
//! Format only - no check digit.
//!
//! Official source: Bureau of Internal Revenue, Revenue Memorandum Order
//! No. 23-91 (3 July 1991) "New Taxpayer Identification Number (TIN)"
//! (republished by the Supreme Court E-Library),
//! <https://elibrary.judiciary.gov.ph/thebookshelf/showdocs/10/49676>,
//! II Policies, A (retrieved 2026-10-31): "The new TIN shall replace the
//! existing TANs, VAT registration numbers, non-VAT registration numbers
//! and withholding tax agent I.D. numbers. It shall consists of a nine (9)
//! digit numeric code. (refer to Annex A for TIN structure)". Annex A is
//! not part of the online text.
//!
//! The validator checks the nine digits, unseparated or grouped
//! `XXX-XXX-XXX`. No check digit is verified (none is in the retrieved
//! text). A branch-code group after the nine digits is not part of the
//! claim: its length is not in the retrieved official text, so in
//! `123-456-789-000` only the nine-digit TIN is matched.
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). The bare tokens "tin" (in "continue", "setting") and
//! "bir" (in "birth") are not cues. Priority tier 7 (national-ID tier);
//! the hyphenated 3-3-3 shape is also the Canadian SIN shape (Luhn, its
//! own cue list) and the bare nine digits are shared with other cue-gated
//! identifiers.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (label forms of the identifier and its issuer).
pub(super) const CUES: &[&str] = &[
    "tin:",
    "tin no",
    "tin number",
    "tin #",
    "taxpayer id",
    "bir tin",
    "bir form",
];

/// Returns `true` if `tin` is a structurally valid Philippine TIN: nine
/// digits, unseparated or written `XXX-XXX-XXX`. There is no officially
/// published check digit, so none is verified.
///
/// # Examples
/// ```
/// use redactify::valid_ph_tin;
/// assert!(valid_ph_tin("123-456-789"));
/// assert!(valid_ph_tin("123456789"));
/// assert!(!valid_ph_tin("123-456-78")); // 8 digits
/// assert!(!valid_ph_tin("123-456-789-000")); // branch group not included
/// ```
#[must_use]
pub fn valid_ph_tin(tin: &str) -> bool {
    let b = tin.as_bytes();
    match b.len() {
        9 => b.iter().all(u8::is_ascii_digit),
        11 => b.iter().enumerate().all(|(i, c)| match i {
            3 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        }),
        _ => false,
    }
}

/// Hyphenated `XXX-XXX-XXX` TIN next to a cue.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        id = "ph::tin",
        EntityType::PhTin,
        r"(?<![\d-])\d{3}-\d{3}-\d{3}(?!\d)",
        Some(valid_ph_tin),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

/// Bare nine-digit TIN next to a cue.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "ph::tin_bare",
        EntityType::PhTin,
        r"(?<![\d-])\d{9}(?![\d-])",
        Some(valid_ph_tin),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_ph_tin;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn nine_digits() {
        for v in ["123-456-789", "123456789", "000000000"] {
            assert!(valid_ph_tin(v), "{v}");
        }
        for v in [
            "123-456-78",
            "12345678",
            "1234567890",
            "123 456 789",
            "123-456789",
            "123-456-789-000",
            "12-3456-789",
        ] {
            assert!(!valid_ph_tin(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required_and_the_branch_group_stays_outside() {
        assert!(engine_detect("business 123-456-789 report", &["ph"]).is_empty());
        assert!(engine_detect("continue 123456789 now", &["ph"]).is_empty());
        let ents = engine_detect("TIN: 123-456-789-000", &["ph"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::PhTin);
        assert_eq!(ents[0].text, "123-456-789");
        let bare = engine_detect("TIN no. 123456789", &["ph"]);
        assert_eq!(bare.len(), 1, "{bare:?}");
        assert_eq!(bare[0].text, "123456789");
    }
}
