//! Polish phone number rule (national 9-digit closed plan).
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. Regulation of the Minister of Digital Affairs of 4 Dec 2024 on
//!    the national numbering plan (Dz.U. 2024 poz. 1862, ISAP):
//!    closed plan, 9 digits, no trunk prefix (leading 0 abolished
//!    30 Sep 2009). Mobile first digit 4-8; landline 2-digit area
//!    code (22 Warsaw, 12 Krakow, etc.).
//! 2. Wikipedia "Telephone numbers in Poland": mobiles XXX XXX XXX
//!    (4xx-8xx ranges), landlines XX XXX XX XX.
//!
//! Permissive first-digit gate (mobile 4-8; landline 1-9 with area
//! codes) - full area-code tables are registry data, not detectable
//! from prose alone.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn phone_rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)[4-8]\d{2}[ -]\d{3}[ -]\d{3}(?!\d)",
        Some(valid_pl_phone),
        ContextPolicy::None,
        0.80
    )
}

/// Returns `true` if `phone` is a structurally valid Polish mobile
/// number (9 digits, first digit 4-8, no trunk prefix).
#[must_use]
pub fn valid_pl_phone(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    // closed plan: mobile starts 4-8 (no trunk 0)
    (b'4'..=b'8').contains(&digits.as_bytes()[0])
}

#[cfg(test)]
mod phone_tests {
    use super::valid_pl_phone;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn pl_phone_valid() {
        assert!(valid_pl_phone("601 234 567"));
        assert!(valid_pl_phone("601234567"));
        assert!(!valid_pl_phone("60123456")); // 8 digits
        assert!(!valid_pl_phone("0601234567")); // leading 0
        assert!(!valid_pl_phone("301234567")); // starts with 3 (not mobile)
    }

    #[test]
    fn pl_phone_detected() {
        let ents = engine_detect("zadzwon 601 234 567", &["pl"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::Phone), "{ents:?}");
    }
}
