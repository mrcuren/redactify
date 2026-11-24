//! US phone number rule.
//! Detects standard US formats: 555-123-4567, (555) 123-4567, 555.123.4567,
//! 555 123 4567. Area code must NOT start with 0 or 1 (NANP rule).
//! Exchange code must NOT start with 0 or 1.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn phone_rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)(?:\+1[ -]?)?(?:\([2-9]\d{2}\)[ -]?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}(?!\d)",
        Some(valid_us_phone),
        ContextPolicy::None,
        0.80
    )
}

/// Returns `true` if `phone` is a structurally valid US phone number
/// (NANP rules: area and exchange codes start 2-9).
#[must_use]
pub fn valid_us_phone(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    // strip country code if present
    let local = if digits.len() == 11 && digits.starts_with('1') {
        &digits[1..]
    } else {
        &digits
    };
    if local.len() != 10 {
        return false;
    }
    // NANP: area code (first 3) and exchange (next 3) must start 2-9
    local.as_bytes()[0] >= b'2'
        && local.as_bytes()[0] <= b'9'
        && local.as_bytes()[3] >= b'2'
        && local.as_bytes()[3] <= b'9'
}

#[cfg(test)]
mod phone_tests {
    use super::valid_us_phone;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn us_phone_valid() {
        // NANP-valid: area and exchange codes start 2-9
        assert!(valid_us_phone("212-555-1234"));
        assert!(valid_us_phone("(212) 555-1234"));
        assert!(valid_us_phone("212.555.1234"));
        assert!(valid_us_phone("+1 212 555 1234"));
        assert!(!valid_us_phone("555-123-4567")); // exchange starts with 1
        assert!(!valid_us_phone("555-012-4567")); // exchange starts with 0
        assert!(!valid_us_phone("055-123-4567")); // area starts with 0
        assert!(!valid_us_phone("1234567890")); // no separators
    }

    #[test]
    fn us_phone_detected() {
        let ents = engine_detect("Call 212-555-1234 for help", &["en"]);
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityType::Phone && e.text == "212-555-1234"),
            "{ents:?}"
        );
        // invalid (area starts with 0) not claimed
        let ents = engine_detect("ref 055-123-4567", &["en"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::Phone),
            "{ents:?}"
        );
    }
}
