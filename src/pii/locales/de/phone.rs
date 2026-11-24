//! German mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (DE mobile): NSN
//! lengths (10, 11) with non-geographic mobile prefixes 15x/16x/17x;
//! example "01512 3456789".
//! Wikipedia "Telephone numbers in Germany": "Mobile numbers are
//! assigned non-geographic area codes starting with 15, 16 and 17";
//! NSN length 10 (16x/17x) or 11 (15xx, 0176, 01609) - i.e. 11-12
//! digits including the trunk 0.
//!
//! FP policy (TR-mobile precedent): the trunk-0 form may appear bare or
//! separated; `01[5-7]` is a prefix superset (unassigned 158/166 blocks
//! not carved out; variable-length digit grouping is left free). No cue
//! (PHONE family, 0.8). Shape-disjoint from the 11-digit Steuer-IdNr
//! (first digit 1-9, never 0).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)01[5-7]\d(?:[ .-]?\d){7,8}(?!\d)",
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
        engine_detect(text, &["de"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn german_mobile_forms_detected() {
        // independent public metadata-set example number + spacing variants
        assert!(is_phone("ruf mich an 01512 3456789 bitte"));
        assert!(is_phone("ruf mich an 015123456789 bitte"));
        assert!(is_phone("nr 0171-2345678 ok")); // 10-digit NSN form
        assert!(is_phone("nr 0160 1234567 ok"));
        // negatives: geographic 030, wrong prefix/length
        assert!(!is_phone("amt 030 1234567 dort"));
        assert!(!is_phone("ref 0181234567 da"));
        assert!(!is_phone("ref 0151234567 da")); // 10 total: NSN 9, not a mobile length
    }
}
