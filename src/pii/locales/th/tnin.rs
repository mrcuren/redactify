//! Thai 13-digit national identification number (เลขประจำตัวประชาชน):
//! validator + rule. Format only - the check digit is not verified.
//!
//! Official sources:
//!
//! 1. Department of Provincial Administration (กรมการปกครอง), Ministry of
//!    Interior, "ความหมายของเลขประจำตัวประชาชน" (page `dopa.go.th/fop/pid13.htm`,
//!    modified 2001-12-26; the page is no longer online, archived copy of
//!    2006-12-25),
//!    <https://web.archive.org/web/20061225122241/http://www.dopa.go.th:80/fop/pid13.htm>
//!    (retrieved 2026-10-30, re-read 2026-10-31): "หลักที่ 1
//!    หมายถึงประเภทบุคคลซึ่งมี 8 ประเภท" (digit 1 is the person type, of
//!    which there are 8, listed as ประเภทที่ 1 to ประเภทที่ 8); digits 2-5
//!    the registration office (2-3 province, 4-5 district); digits 6-10
//!    the group; digits 11-12 the sequence in the group; "หลักที่ 13 คือ
//!    ตัวเลขตรวจสอบความถูกต้องของเลข 12 หลักแรก" (digit 13 is the check
//!    digit of the first 12).
//! 2. The Revenue Department, "Thailand - Information on Tax
//!    Identification Numbers" (country sheet published on the OECD AEOI
//!    portal, PDF of 2025-12-09),
//!    <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/thailand-tin.pdf>,
//!    Section II (retrieved 2026-10-31): "A Tax Identification Number
//!    (TIN) consists of 13 digits ... Digits 1-3 indicate the issuing
//!    agency - Numbers 100-999: issued by the Department of Provincial
//!    Administration, Ministry of Interior (except 601). ... Digit 13 is
//!    the check digit, calculated using the same method applied to the
//!    13-digit identification numbers issued by the Department of
//!    Provincial Administration."
//!
//! The validator checks 13 digits, a person type (first digit) of 1-8
//! (DOPA) and a first three digits other than `601` (Revenue
//! Department). The check digit is not verified: neither source publishes
//! its computation.
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). A leading cue counts when its END lies within the
//! 18-character cue window before the value (`pii::context`), so the full
//! 18-character label "เลขประจำตัวประชาชน" is a cue; its tail
//! "ประจำตัวประชาชน" stays as the catch-all for the other phrasings (e.g.
//! "บัตรประจำตัวประชาชน", the identity card).
//!
//! Priority: tier 0, as for the Korean registration numbers: about 10% of
//! 13-digit values pass Luhn and the cue-less card rule would relabel
//! them. The `th` pack is registered before `za`, whose cue-less ID rule
//! shares tier 0 and the 13-digit shape.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (the identifier's Thai and English names). The
/// abbreviation "TNIN" is delimited (`tnin:`, `tnin `, `(tnin)`): bare, it
/// is a substring of the Swedish "drottning".
pub(super) const CUES: &[&str] = &[
    "เลขประจำตัวประชาชน",
    "ประจำตัวประชาชน",
    "บัตรประชาชน",
    "thai id",
    "national id",
    "tnin:",
    "tnin ",
    "(tnin)",
];

/// Returns `true` if `id` is a structurally valid Thai national
/// identification number: 13 digits, first digit (person type) 1-8 and
/// first three digits other than `601`. The check digit is not verified
/// (its algorithm is not officially published).
///
/// # Examples
/// ```
/// use redactify::valid_th_tnin;
/// assert!(valid_th_tnin("1234567890123"));
/// assert!(!valid_th_tnin("0123456789012")); // person type 0
/// assert!(!valid_th_tnin("9123456789012")); // person type 9
/// assert!(!valid_th_tnin("6012345678901")); // prefix 601
/// ```
#[must_use]
pub fn valid_th_tnin(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 13
        && b.iter().all(u8::is_ascii_digit)
        && matches!(b[0], b'1'..=b'8')
        && &b[..3] != b"601"
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ThTnin,
        r"(?<![\d-])[1-8]\d{12}(?![\d-])",
        Some(valid_th_tnin),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_th_tnin;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn person_type_and_prefix() {
        for v in ["1234567890123", "8999999999999", "6002345678901"] {
            assert!(valid_th_tnin(v), "{v}");
        }
        for v in [
            "0123456789012",
            "9123456789012",
            "6012345678901",
            "110170023070",
            "12345678901231",
            "1-1017-00230-70-5",
        ] {
            assert!(!valid_th_tnin(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("order 1234567890123 shipped", &["th"]).is_empty());
        for text in [
            "เลขประจำตัวประชาชน 1234567890123",
            "บัตรประชาชน: 1234567890123",
            "Thai ID 1234567890123",
        ] {
            let ents = engine_detect(text, &["th"]);
            assert_eq!(ents.len(), 1, "{text}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::ThTnin);
            assert!((ents[0].score - 0.9).abs() < 1e-6);
        }
    }
}
