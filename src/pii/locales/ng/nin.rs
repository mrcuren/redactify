//! Nigerian National Identity Number (NIN): validator + rule. Format only -
//! no check digit.
//!
//! Official source: Nigerian Communications Commission, FAQ "About The
//! NIN", <https://ncc.gov.ng/node/736>, question "What is NIN?" (retrieved
//! 2026-10-31): "NIN which stands for National Identity Number is the
//! 11-digit number that uniquely identifies you either as a citizen of
//! Nigeria, or as a foreigner legally resident in Nigeria. The NIN is
//! issued upon enrolment by the National Identity Management Commission
//! (NIMC)."
//!
//! The validator checks the 11 digits. No check digit is verified: no
//! NIMC or NCC document publishing one was found.
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). The bare token "nin" is not a cue (it is a substring
//! of "running", "nine", "dining"). A leading cue counts when its END lies
//! within the 18-character cue window before the value (`pii::context`),
//! so the long labels "national identity number" (the NCC wording quoted
//! above) and "national identification number" are cues in full: the
//! prefix "national id" alone ends more than 18 characters before a value
//! written after "National Identification Number: ".
//!
//! Priority tier 7 (national-ID tier). The 11-digit shape is also the
//! Turkish TCKN shape, claimed cue-less at tier 3: with `tr` enabled a NIN
//! that happens to pass both TCKN check digits keeps the TCKN label (the
//! value is masked either way).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (label forms of the identifier and its issuer).
pub(super) const CUES: &[&str] = &[
    "nin:",
    "nin no",
    "nin number",
    "nimc",
    "national identity number",
    "national identification number",
    "national id",
];

/// Returns `true` if `nin` is a structurally valid Nigerian NIN: exactly
/// 11 ASCII digits. There is no officially published check digit, so none
/// is verified.
///
/// # Examples
/// ```
/// use redactify::valid_ng_nin;
/// assert!(valid_ng_nin("12345678901"));
/// assert!(!valid_ng_nin("1234567890")); // 10 digits
/// assert!(!valid_ng_nin("123456789012")); // 12 digits
/// ```
#[must_use]
pub fn valid_ng_nin(nin: &str) -> bool {
    nin.len() == 11 && nin.bytes().all(|b| b.is_ascii_digit())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::NgNin,
        r"(?<![\d.\-])\d{11}(?![\d\-])",
        Some(valid_ng_nin),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_ng_nin;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn eleven_digits() {
        assert!(valid_ng_nin("00000000000"));
        for v in ["1234567890", "123456789012", "1234567890a", "1234 5678901"] {
            assert!(!valid_ng_nin(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required_and_substring_traps_stay_silent() {
        assert!(engine_detect("order 12345678901 shipped", &["ng"]).is_empty());
        assert!(engine_detect("running 12345678901 laps", &["ng"]).is_empty());
        assert!(engine_detect("nine 12345678901 items", &["ng"]).is_empty());
        for text in [
            "NIN: 12345678901",
            "NIMC slip 12345678901",
            "national ID 12345678901",
        ] {
            let ents = engine_detect(text, &["ng"]);
            assert_eq!(ents.len(), 1, "{text}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::NgNin);
            assert!((ents[0].score - 0.9).abs() < 1e-6);
        }
    }
}
