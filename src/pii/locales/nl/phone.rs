//! Dutch mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (NL mobile): NSN 9
//! digits starting 6 (mobile subscriber block 6[1-58]); example
//! "06 12345678".
//! Wikipedia "Telephone numbers in the Netherlands": mobiles are "06"
//! followed by eight digits, always 10 digits total, grouped "06 xx xx
//! xx xx".
//!
//! FP policy (TR-mobile precedent): the trunk-0 form may appear bare
//! (`0612345678`) or separated; the `06` prefix is a superset of the
//! 061-065/068 mobile blocks (service blocks like 066 are not modelled).
//! No cue (PHONE family, score 0.8). The shape coincides with the FR
//! 06-mobile shape by design: both rules yield the same PHONE entity, so
//! fr+nl co-activation cannot produce a conflict.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)06(?:[ .-]?\d){8}(?!\d)",
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
        engine_detect(text, &["nl"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn dutch_mobile_forms_detected() {
        assert!(is_phone("bel me op 06 12345678 aub"));
        assert!(is_phone("bel me op 0612345678 aub"));
        assert!(is_phone("nr 06-12-34-56-78 ok"));
        // negatives
        assert!(!is_phone("ref 0512345678 staan")); // 05 geographic
        assert!(!is_phone("ref 061234567 staan"));
    }
}
