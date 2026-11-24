//! Australian phone number rule (national format with trunk prefix 0).
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. ACMA (regulator) "Choose your phone number" / Telecommunications
//!    Numbering Plan 2021: mobile 04XX XXX XXX; landline (0X) XXXX XXXX
//!    with area codes 02 NSW/ACT, 03 VIC/TAS, 07 QLD, 08 WA/SA/NT.
//! 2. Wikipedia "Telephone numbers in Australia": trunk prefix 0,
//!    mobile 04, landline (0[2378]).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn phone_rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)0[2378]\d{3}[ -]\d{4}(?!\d)|(?<!\d)04\d{2}[ -]\d{3}[ -]\d{3}(?!\d)",
        Some(valid_au_phone),
        ContextPolicy::None,
        0.80
    )
}

/// Returns `true` if `phone` is a structurally valid Australian phone
/// number (10 digits starting with 02/03/04/07/08).
#[must_use]
pub fn valid_au_phone(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 10 {
        return false;
    }
    // trunk prefix 0 + area code 2/3/4/7/8
    matches!(digits.as_bytes()[1], b'2' | b'3' | b'4' | b'7' | b'8')
}

#[cfg(test)]
mod phone_tests {
    use super::valid_au_phone;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn au_phone_valid() {
        assert!(valid_au_phone("0412 345 678"));
        assert!(valid_au_phone("(02) 9876 5432"));
        assert!(!valid_au_phone("412 345 678")); // missing trunk 0
        assert!(!valid_au_phone("061 2345 678")); // no 06 area code
    }

    #[test]
    fn au_phone_detected() {
        let ents = engine_detect("call 0412 345 678", &["au"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::Phone), "{ents:?}");
    }
}
