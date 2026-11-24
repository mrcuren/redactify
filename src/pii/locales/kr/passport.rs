//! South Korean passport number (여권번호): validator + rule. Format only -
//! no check digit.
//!
//! Official sources:
//!
//! 1. Ministry of Culture, Sports and Tourism and Ministry of Foreign
//!    Affairs, joint press release "차세대 전자여권 디자인 시안 공개"
//!    (2018-10-15), <https://www.mcst.go.kr/kor/s_notice/press/pressView.jsp?pSeq=16931>,
//!    table "주요 변경사항", row "여권번호" (retrieved 2026-10-30):
//!    "여권번호 체계 변경(영문자 1자리 추가) (M12345678 -> M123A4567)"
//!    (passport number system change, one letter added).
//! 2. Ministry of Foreign Affairs, press release [21-903] "차세대 전자여권
//!    올해 12.21.(화)부터 전면 발급 개시" (2021-11-11),
//!    <https://www.mofa.go.kr/www/brd/m_4080/view.do?seq=371764>
//!    (retrieved 2026-10-30): the next-generation passport, issued from
//!    21 December 2021, comes with "여권번호 체계 변경" (the changed
//!    passport number system).
//!
//! Formats: the earlier letter + 8 digits (`M12345678`) and the current
//! letter + 3 digits + letter + 4 digits (`M123A4567`). The sources show
//! only `M` as the first letter and define no letter set, so any
//! uppercase letter is accepted in both letter positions (structural;
//! the first letter is not narrowed).
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). Priority tier 6 (passport tier). The earlier format
//! is also the US passport shape with the shared cue "passport"; with both
//! packs enabled the equal-tier, equal-span tie goes to the `en` rule,
//! registered first, while the Korean cue "여권" selects this rule only.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (the document's Korean and English names).
pub(super) const CUES: &[&str] = &["여권", "passport"];

/// Returns `true` if `passport` is a structurally valid South Korean
/// passport number: an uppercase letter followed by 8 digits (earlier
/// format) or by 3 digits, an uppercase letter and 4 digits (format issued
/// since 21 December 2021). There is no check digit.
///
/// # Examples
/// ```
/// use redactify::valid_kr_passport;
/// assert!(valid_kr_passport("M12345678")); // official example
/// assert!(valid_kr_passport("M123A4567")); // official example
/// assert!(!valid_kr_passport("M1234A567")); // letter in the wrong place
/// assert!(!valid_kr_passport("M1234567")); // 8 characters
/// ```
#[must_use]
pub fn valid_kr_passport(passport: &str) -> bool {
    let b = passport.as_bytes();
    if b.len() != 9 || !b[0].is_ascii_uppercase() {
        return false;
    }
    let digits = |r: &[u8]| r.iter().all(u8::is_ascii_digit);
    digits(&b[1..]) || (digits(&b[1..4]) && b[4].is_ascii_uppercase() && digits(&b[5..]))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::KrPassport,
        r"(?<![A-Za-z0-9])[A-Z](?:\d{8}|\d{3}[A-Z]\d{4})(?![A-Za-z0-9])",
        Some(valid_kr_passport),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_kr_passport;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn both_formats() {
        for v in ["M12345678", "M123A4567", "S98765432", "R001Z0001"] {
            assert!(valid_kr_passport(v), "{v}");
        }
        for v in [
            "M1234567",   // 8 characters
            "M1234A567",  // letter in position 6
            "MM23A4567",  // second character a letter
            "m123a4567",  // lower case
            "M123A45678", // 10 characters
            "123456789",  // no letter
        ] {
            assert!(!valid_kr_passport(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("ticket M123A4567 closed", &["kr"]).is_empty());
        for text in ["여권번호 M123A4567", "passport no M12345678"] {
            let ents = engine_detect(text, &["kr"]);
            assert_eq!(ents.len(), 1, "{text}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::KrPassport);
        }
    }
}
