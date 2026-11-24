//! French mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (FR mobile): NSN 9
//! digits starting 6/7 (with range holes); example "06 12 34 56 78".
//! Wikipedia "Telephone numbers in France": "06 Mobile phone services",
//! "07 Mobile phone services"; numbers "usually stated as a sequence of
//! five digit-pairs" (0x xx xx xx xx).
//!
//! FP policy (TR-mobile precedent): the trunk-0 form may appear bare
//! (`0612345678`) or pair-separated (`06 12 34 56 78`); the prefix set
//! `0[67]` is a superset of the assigned mobile ranges (the engine does
//! not model per-operator holes). No cue (PHONE family, score 0.8).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)0[67](?:[ .-]?\d){8}(?!\d)",
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
        engine_detect(text, &["fr"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn french_mobile_forms_detected() {
        // independent public metadata-set example number + spacing variants
        assert!(is_phone("rappelle-moi au 06 12 34 56 78 stp"));
        assert!(is_phone("rappelle-moi au 0612345678 stp"));
        assert!(is_phone("num 06-12-34-56-78 ok"));
        assert!(is_phone("num 07.12.34.56.78 ok")); // 07 mobiles
                                                    // negatives: wrong prefix, wrong length
        assert!(!is_phone("ligne 08 12 34 56 78 ici")); // 08 = special
        assert!(!is_phone("ref 061234567 standby"));
        assert!(!is_phone("ref 06123456789 standby"));
    }
}
