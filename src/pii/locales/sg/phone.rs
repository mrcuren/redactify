//! Singapore phone number rule (8-digit uniform plan).
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. IMDA National Numbering Plan: 8-digit uniform numbers, no area
//!    codes, no trunk prefix. Landline starts 6, mobile 8 or 9, VoIP 3.
//! 2. Wikipedia "Telephone numbers in Singapore": same ranges.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn phone_rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)[3689]\d{3}[ -]\d{4}(?!\d)",
        Some(valid_sg_phone),
        ContextPolicy::None,
        0.80
    )
}

/// Returns `true` if `phone` is a structurally valid Singapore phone
/// number (8 digits starting 3/6/8/9).
#[must_use]
pub fn valid_sg_phone(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 8 {
        return false;
    }
    matches!(digits.as_bytes()[0], b'3' | b'6' | b'8' | b'9')
}

#[cfg(test)]
mod phone_tests {
    use super::valid_sg_phone;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn sg_phone_valid() {
        assert!(valid_sg_phone("6123 4567"));
        assert!(valid_sg_phone("81234567"));
        assert!(!valid_sg_phone("51234567")); // 5 unassigned
        assert!(!valid_sg_phone("6123456")); // 7 digits
    }

    #[test]
    fn sg_phone_detected() {
        let ents = engine_detect("call 8123 4567", &["sg"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::Phone), "{ents:?}");
    }
}
