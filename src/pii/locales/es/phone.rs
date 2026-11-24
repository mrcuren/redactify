//! Spanish mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (ES mobile): NSN 9
//! digits `(?:6\d|7[1-48])\d{7}`; example "612 34 56 78".
//! Wikipedia "Telephone numbers in Spain": "Mobile phone numbers begin
//! with 6 or 7, followed by 8 digits", no leading zero; 70 is the
//! personal-number block.
//!
//! FP policy (TR-landline precedent): a SEPARATOR-BEARING form is
//! required (3-3-3 `612 345 678` or 3-2-2-2 `612 34 56 78`) - a bare
//! 9-digit run is never a Spanish mobile, which keeps bare
//! BSN/VKN/order-number shapes unclaimed. The prefix superset follows
//! the metadata set's second-digit class (7[1-48], excluding the 70
//! personal block). No cue (PHONE family, 0.8).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)(?:6\d|7[1-48])\d(?:[ .-]\d{3}[ .-]\d{3}|(?:[ .-]\d{2}){3})(?!\d)",
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
        engine_detect(text, &["es"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn spanish_mobile_forms_detected() {
        // independent public metadata-set example number + spacing variants
        assert!(is_phone("llamame al 612 34 56 78 porfa"));
        assert!(is_phone("llamame al 612 345 678 porfa"));
        assert!(is_phone("num 612-345-678 ok"));
        assert!(is_phone("num 712 345 678 ok")); // 7xx mobiles
                                                 // negatives: bare 9-digit runs are never claimed (BSN/VKN shapes)
        assert!(!is_phone("ref 612345678 aqui"));
        assert!(!is_phone("linea 701 234 567 alla")); // 70 personal
        assert!(!is_phone("ref 612 3456 78 aqui")); // 3-4-2 grouping
    }
}
