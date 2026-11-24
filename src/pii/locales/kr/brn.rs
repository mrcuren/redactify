//! South Korean business registration number (사업자등록번호, BRN):
//! validator + rule. Format only - no check digit.
//!
//! Official source: National Tax Service, "Republic of Korea -
//! Information on Tax Identification Numbers" (country sheet published on
//! the OECD AEOI portal, "Last update 30, May, 2023"),
//! <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/korea-tin.pdf>,
//! Section II "TIN Structure" (retrieved 2026-10-30): "A Business
//! Registration Number consists of 10 digits. - TIN structure :
//! XXX-XX-XXXXX".
//!
//! The validator checks the 10 digits in the `XXX-XX-XXXXX` structure (or
//! unseparated). No check digit is verified: no official source publishes
//! one. The rule claims only the hyphenated structure the source gives; a
//! bare 10-digit run is shared with many other identifiers and is not
//! claimed.
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). Priority tier 7 (national-ID tier): the 3-2-5 shape
//! overlaps no other rule's span.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (the identifier's Korean and English names).
pub(super) const CUES: &[&str] = &[
    "사업자등록번호",
    "사업자번호",
    "사업자 등록",
    "business reg",
    "brn",
];

/// Returns `true` if `brn` is a structurally valid South Korean business
/// registration number: 10 digits written `XXX-XX-XXXXX` or unseparated.
/// There is no officially published check digit, so none is verified.
///
/// # Examples
/// ```
/// use redactify::valid_kr_brn;
/// assert!(valid_kr_brn("123-45-67890"));
/// assert!(valid_kr_brn("1234567890"));
/// assert!(!valid_kr_brn("123-45-6789")); // last group has 4 digits
/// assert!(!valid_kr_brn("1234-56-78901"));
/// ```
#[must_use]
pub fn valid_kr_brn(brn: &str) -> bool {
    let b = brn.as_bytes();
    match b.len() {
        10 => b.iter().all(u8::is_ascii_digit),
        12 => b.iter().enumerate().all(|(i, c)| match i {
            3 | 6 => *c == b'-',
            _ => c.is_ascii_digit(),
        }),
        _ => false,
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::KrBrn,
        r"(?<![\d-])\d{3}-\d{2}-\d{5}(?![\d-])",
        Some(valid_kr_brn),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_kr_brn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure() {
        assert!(valid_kr_brn("123-45-67890"));
        assert!(valid_kr_brn("0000000000"));
        for v in [
            "123-45-6789",
            "1234-56-78901",
            "12-345-67890",
            "123 45 67890",
            "123-45-6789a",
            "12345678901",
        ] {
            assert!(!valid_kr_brn(v), "{v}");
        }
    }

    #[test]
    fn hyphenated_with_cue_only() {
        assert!(engine_detect("ref 123-45-67890 filed", &["kr"]).is_empty());
        // the bare form is not claimed even next to a cue
        assert!(engine_detect("사업자등록번호 1234567890", &["kr"]).is_empty());
        let ents = engine_detect("사업자등록번호: 123-45-67890", &["kr"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::KrBrn);
        // an SSN-shaped 3-2-4 run is not a BRN
        assert!(engine_detect("BRN 123-45-6789", &["kr"]).is_empty());
    }
}
