//! Italian mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (IT mobile): NSN
//! 9-10 digits starting 3 (`3[2-9]\d{7,8}` plus ported 31/43 blocks);
//! example "312 345 6789".
//! Wikipedia "Telephone numbers in Italy": mobiles start with 3, are
//! "generally ten digits long" with rare nine-digit ones; the leading 0
//! "has been removed" (2001); grouping has "no fixed rules" (spaces,
//! dots and hyphens are all used).
//!
//! FP policy (TR-landline precedent): a SEPARATOR-BEARING form is
//! required (3-3-3 / 3-3-4, e.g. `312 345 6789`) - a bare 9-10 digit
//! run is never an Italian mobile, keeping bare BSN/VKN/order shapes
//! unclaimed. Prefix superset `3\d` (operator holes not modelled). No
//! cue (PHONE family, 0.8).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)3\d{2}[ .-]\d{3}[ .-]\d{3,4}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    fn is_phone(text: &str) -> bool {
        engine_detect(text, &["it"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn italian_mobile_forms_detected() {
        // independent public metadata-set example number + spacing variants
        assert!(is_phone("chiamami al 312 345 6789 grazie"));
        assert!(is_phone("num 345 123 456 ok")); // 9-digit form
        assert!(is_phone("num 345-123-4567 ok"));
        // negatives: bare runs never claimed; geographic 02x separated
        assert!(!is_phone("ref 3123456789 qui"));
        assert!(!is_phone("ref 312345678 qui"));
        assert!(!is_phone("ufficio 02 1234567 li"));
    }
}
