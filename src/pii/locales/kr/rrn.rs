//! South Korean resident registration number (주민등록번호, RRN):
//! validator + rule. Birth-date and gender-digit validation only - no
//! check digit.
//!
//! Official sources:
//!
//! 1. National Tax Service, "Republic of Korea - Information on Tax
//!    Identification Numbers" (country sheet published on the OECD AEOI
//!    portal, "Last update 30, May, 2023"),
//!    <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/korea-tin.pdf>,
//!    Section II "TIN Structure" (retrieved 2026-10-30): "A Resident
//!    Registration Number consists of 13 digits (XXXXXX-XXXXXXX) and is
//!    assigned based on the following criteria: (a) It is made up of an
//!    individual's date of birth with 6 digits. For example, a person born
//!    on Januay 2, 1985 has the first six digit such as 850102. (b) It
//!    identifies the sex of individuals." The accompanying table (read
//!    from the text layer): "Koreans: before 2000 Male 1 Female 2; after
//!    2000 Male 3 Female 4; Foreigners: before 2000 Male 5 Female 6; after
//!    2000 Male 7 Female 8".
//! 2. Ministry of the Interior and Safety, press release "45년만에
//!    주민등록번호 부여체계 바꾼다" (2019-12-17),
//!    <https://www.mois.go.kr/frt/bbs/type010/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000008&nttId=74731>
//!    (retrieved 2026-10-30): "내년 10월부터 주민등록번호 뒷자리에
//!    지역번호를 없애고 임의번호를 부여하는 방식으로 주민등록번호
//!    부여체계를 개편한다" (from October 2020 the region code in the back
//!    part is replaced by a random number).
//! 3. Ministry of the Interior and Safety briefing on korea.kr
//!    (2020-05-25), <https://www.korea.kr/briefing/policyBriefingView.do?newsId=148872723>
//!    (retrieved 2026-10-30): "뒷자리는 성별 표시 첫 자리를 제외하고
//!    6자리의 임의번호를 부여받게 된다" (the back part is the gender digit
//!    followed by six random digits).
//!
//! The validator checks the 13-digit shape (`YYMMDD-GNNNNNN` or
//! unseparated), a gender digit `G` of 1-4 (Koreans: 1/2 born before
//! 2000, 3/4 from 2000) and a real calendar date in that century. No check
//! digit: no official source publishes one, and numbers assigned since
//! October 2020 end in random digits. Gender digits 5-8 are the
//! foreigner registration number (`kr::frn`).
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum).
//!
//! Priority: tier 0 (see `EntityType::priority`). About 10% of 13-digit
//! values also pass Luhn, so the cue-less card rule would otherwise
//! relabel a cued RRN as a card number (CN_RESIDENT_ID precedent). The
//! `kr` pack is registered before `za`, whose cue-less ID rule shares tier
//! 0 and the 13-digit shape.

use super::valid_registration;
use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (the identifier's Korean and English names).
pub(super) const CUES: &[&str] = &[
    "주민등록번호",
    "주민번호",
    "주민 등록",
    "resident reg",
    "rrn",
];

/// Birth century of an RRN gender digit (NTS table, Koreans).
fn century(g: u8) -> Option<u32> {
    match g {
        b'1' | b'2' => Some(1900),
        b'3' | b'4' => Some(2000),
        _ => None,
    }
}

/// Returns `true` if `rrn` is a structurally valid South Korean resident
/// registration number: 13 digits written `YYMMDD-GNNNNNN` or
/// `YYMMDDGNNNNNN`, gender digit `G` 1-4 (1/2: born 1900-1999, 3/4: born
/// 2000-2099) and a real calendar birth date. There is no check digit.
///
/// # Examples
/// ```
/// use redactify::valid_kr_rrn;
/// assert!(valid_kr_rrn("850102-1234567")); // NTS example date 850102
/// assert!(valid_kr_rrn("0002294234567")); // 29 Feb 2000
/// assert!(!valid_kr_rrn("850230-1234567")); // 30 February
/// assert!(!valid_kr_rrn("850102-5234567")); // 5 is a foreigner digit
/// ```
#[must_use]
pub fn valid_kr_rrn(rrn: &str) -> bool {
    valid_registration(rrn, century)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::KrRrn,
        r"(?<![\d-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[1-4]\d{6}(?![\d-])",
        Some(valid_kr_rrn),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_kr_rrn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn gender_digit_and_date() {
        for v in [
            "850102-1234567",
            "850102-2234567",
            "8501021234567",
            "000101-3234567",
            "000229-4234567", // 2000 is a leap year
            "960229-1234567", // 1996 is a leap year
        ] {
            assert!(valid_kr_rrn(v), "{v}");
        }
        for v in [
            "850230-1234567", // 30 February
            "851302-1234567", // month 13
            "850100-1234567", // day 0
            "000229-1234567", // 29 Feb 1900 does not exist
            "850102-0234567", // gender digit 0
            "850102-5234567", // foreigner digit
            "850102-9234567", // not in the table
            "850102-123456",  // 12 digits
            "85010-21234567", // misplaced separator
            "850102 1234567", // foreign separator
        ] {
            assert!(!valid_kr_rrn(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("order 850102-1234567 shipped", &["kr"]).is_empty());
        for text in ["주민등록번호 850102-1234567", "RRN: 8501021234567"] {
            let ents = engine_detect(text, &["kr"]);
            assert_eq!(ents.len(), 1, "{text}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::KrRrn);
            assert!((ents[0].score - 0.9).abs() < 1e-6);
        }
    }
}
