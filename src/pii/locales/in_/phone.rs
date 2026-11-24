//! Indian phone number rule: mobile numbers only, 10 digits starting 6-9,
//! written as two groups of five separated by a space or hyphen.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. DoT (Government of India) National Numbering Plan: mobile 10
//!    digits, first digit 6-9; landline = trunk 0 + STD code (2-4
//!    digits) + subscriber number (6-8 digits, starts 2-6).
//! 2. Wikipedia "Telephone numbers in India": mobile 10 digits
//!    starting 6-9; STD codes 11 Delhi, 22 Mumbai, 33 Kolkata, 80
//!    Bengaluru, etc.
//!
//! Scope (precision-first): landlines and a bare 10-digit run are not
//! claimed.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn phone_rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)[6-9]\d{4}[ -]\d{5}(?!\d)",
        Some(valid_in_phone),
        ContextPolicy::None,
        0.80
    )
}

/// Returns `true` if `phone` is a structurally valid Indian mobile
/// number (10 digits, first digit 6-9).
#[must_use]
pub fn valid_in_phone(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 10 {
        return false;
    }
    (b'6'..=b'9').contains(&digits.as_bytes()[0])
}

#[cfg(test)]
mod phone_tests {
    use super::valid_in_phone;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn in_phone_valid() {
        assert!(valid_in_phone("98765 43210"));
        assert!(valid_in_phone("98765 43210"));
        assert!(!valid_in_phone("1234567890")); // starts with 1
        assert!(!valid_in_phone("987654321")); // 9 digits
    }

    #[test]
    fn in_phone_detected() {
        let ents = engine_detect("call 98765 43210", &["in"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::Phone), "{ents:?}");
    }
}
