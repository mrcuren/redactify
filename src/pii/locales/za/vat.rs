//! South African VAT registration number: validator + rule. Format only -
//! no check digit.
//!
//! Official source: South African Revenue Service, GEN-ELEC-04-G01 "Guide
//! to completing the Value Added Tax VAT201 Declaration" (External Guide,
//! Revision 11),
//! <https://www.sars.gov.za/wp-content/uploads/Ops/Guides/GEN-ELEC-04-G01-Guide-for-completing-the-Value-Added-Tax-VAT201-Declaration-External-Guide.pdf>,
//! section "VAT Registration Number" (retrieved 2026-10-31): "The VAT
//! registration number is the 10-digit number allocated by SARS to a
//! registered vendor."
//!
//! The validator checks the 10 digits. Not checked: a leading `4` (seen
//! only in secondary sources; the guide's payment-reference example
//! `4123456789...` is an illustration, not a rule) and any check digit
//! (none is published; that example does not pass the SARS modulus 10
//! check either).
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum). Priority tier 7 (national-ID tier). The run must not
//! touch an ASCII letter or digit, so a country-prefixed EU VAT number is
//! never cut short.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (label forms of the VAT registration number).
pub(super) const CUES: &[&str] = &["vat no", "vat number", "vat reg", "vat:"];

/// Returns `true` if `vat` is a structurally valid South African VAT
/// registration number: exactly 10 ASCII digits. There is no officially
/// published check digit, so none is verified.
///
/// # Examples
/// ```
/// use redactify::valid_za_vat;
/// assert!(valid_za_vat("4123456789"));
/// assert!(!valid_za_vat("412345678")); // 9 digits
/// assert!(!valid_za_vat("41234567890")); // 11 digits
/// ```
#[must_use]
pub fn valid_za_vat(vat: &str) -> bool {
    vat.len() == 10 && vat.bytes().all(|b| b.is_ascii_digit())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ZaVat,
        r"(?<![0-9A-Za-z\-])\d{10}(?![0-9A-Za-z\-])",
        Some(valid_za_vat),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_za_vat;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn ten_digits() {
        assert!(valid_za_vat("4123456789"));
        assert!(valid_za_vat("0123456789"));
        for v in ["412345678", "41234567890", "412345678a", "4123 456789"] {
            assert!(!valid_za_vat(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("batch 4123456789 shipped", &["za"]).is_empty());
        let ents = engine_detect("VAT reg. no. 4123456789", &["za"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::ZaVat);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
        // a prefixed EU VAT number is not cut short
        assert!(engine_detect("VAT number PL4123456789", &["za"]).is_empty());
    }
}
