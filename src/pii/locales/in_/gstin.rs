//! Indian GSTIN (Goods and Services Tax Identification Number):
//! validator + rule.
//!
//! Official sources:
//!
//! 1. Central Goods and Services Tax Rules, 2017, Rule 10(1) "Issue of
//!    registration certificate" (CBIC tax information portal, archived
//!    copy because the live site resets the connection),
//!    <https://web.archive.org/web/2024/https://taxinformation.cbic.gov.in/content/html/tax_repository/gst/rules/cgst_rules/documents/Central_Goods_and_Services_Tax_Rules__2017_26-December-2022.html>,
//!    Rule 10(1)(a)-(d) (retrieved 2026-10-30): "a Goods and Services Tax
//!    Identification Number shall be assigned subject to the following
//!    characters, namely: - (a) two characters for the State code; (b) ten
//!    characters for the Permanent Account Number or the Tax Deduction and
//!    Collection Account Number; (c) two characters for the entity code;
//!    and (d) one checksum character."
//! 2. GST Council flyer "Registration under GST Law",
//!    <https://gstcouncil.gov.in/sites/default/files/e-version-gst-flyers/Registration_under_GST_Law_new.pdf>,
//!    GSTIN paragraph (retrieved 2026-10-30): "The first 2 digits of the
//!    GSTIN is the State code, next 10 digits are the PAN of the legal
//!    entity, the next two digits are for entity code, and the last digit
//!    is check sum number."
//!
//! Structure checked: two digits (State code), a structurally valid PAN
//! (the existing [`valid_in_pan`] rules), then three characters
//! `[0-9A-Z]` (entity code + checksum character). Not checked, because no
//! official source defines them: the checksum algorithm (Rule 10(1)(d)
//! names a checksum character but does not publish its computation), the
//! State-code range (no official list was retrieved), a fixed letter in
//! the entity-code positions, and the TAN-based variant (no official TAN
//! format was retrieved).
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). The bare token "gst" is not a cue (it is a
//! substring of e.g. "angstrom"; PAN "pan" precedent). A leading cue
//! counts when its END lies within the 18-character cue window before the
//! value (`pii::context`), so the Rule 10 label "Goods and Services Tax
//! Identification Number" is a cue in full, and "goods and services tax"
//! covers the shorter label forms ("Goods and Services Tax No.").

use crate::pii::entity::EntityType;
use crate::pii::locales::in_::pan::valid_in_pan;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase substring matching) that make a GSTIN candidate
/// claimable.
pub(super) const CUES: &[&str] = &[
    "gstin",
    "goods and services tax identification number",
    "goods and services tax",
    "gst no",
    "gst number",
    "gst reg",
    "gst:",
    "gst in",
];

/// Returns `true` if `gstin` is a structurally valid GSTIN: 15 characters,
/// two digits (State code), a structurally valid PAN (see
/// [`valid_in_pan`]) and three characters `[0-9A-Z]` (entity code and
/// checksum character). The checksum character is not verified: its
/// algorithm is not officially published.
///
/// # Examples
/// ```
/// use redactify::valid_in_gstin;
/// assert!(valid_in_gstin("27AFZPK7190K1Z5")); // structural test value
/// assert!(!valid_in_gstin("27AFZDK7190K1Z5")); // PAN holder letter D
/// assert!(!valid_in_gstin("27AFZPK0000K1Z5")); // PAN serial 0000
/// assert!(!valid_in_gstin("27AFZPK7190K1Z")); // 14 characters
/// ```
#[must_use]
pub fn valid_in_gstin(gstin: &str) -> bool {
    let b = gstin.as_bytes();
    if b.len() != 15 || !b.is_ascii() {
        return false;
    }
    b[..2].iter().all(u8::is_ascii_digit)
        && valid_in_pan(&gstin[2..12])
        && b[12..]
            .iter()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::InGstin,
        r"(?<![0-9A-Z])\d{2}[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z][0-9A-Z]{3}(?![0-9A-Z])",
        Some(valid_in_gstin),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_in_gstin;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure() {
        // built on the PAN example of the Income Tax Department's OECD
        // TIN sheet (AFZPK7190K); not a real GSTIN
        assert!(valid_in_gstin("27AFZPK7190K1Z5"));
        assert!(valid_in_gstin("01AFZPK7190K9A9"));
        for v in [
            "27AFZDK7190K1Z5",  // holder letter D
            "27AFZPK0000K1Z5",  // serial 0000
            "27AFZPK7190K1Z",   // 14 characters
            "27AFZPK7190K1Z55", // 16 characters
            "2AAFZPK7190K1Z5",  // State code not numeric
            "27afzpk7190k1z5",  // lower case
            "27AFZPK7190K1z5",  // lower-case entity code
            "27AFZPK7190K1Z-",  // foreign character
        ] {
            assert!(!valid_in_gstin(v), "{v}");
        }
        assert!(!valid_in_gstin("27AFZPK7190K1Zé"));
    }

    #[test]
    fn cue_is_required_and_pan_stays_silent_inside() {
        assert!(engine_detect("invoice 27AFZPK7190K1Z5 paid", &["in"]).is_empty());
        let ents = engine_detect("GSTIN: 27AFZPK7190K1Z5", &["in"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::InGstin);
        assert_eq!(ents[0].text, "27AFZPK7190K1Z5");
        assert!((ents[0].score - 0.9).abs() < 1e-6);
        // the embedded PAN is never claimed on its own, even with a PAN cue
        let pan = engine_detect("PAN: 27AFZPK7190K1Z5", &["in"]);
        assert!(pan.is_empty(), "{pan:?}");
    }
}
