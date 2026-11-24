//! UK mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (GB mobile): NSN 10
//! digits starting 7 (with range holes for personal/pager blocks);
//! example "07400 123456".
//! Wikipedia "Telephone numbers in the United Kingdom": mobile
//! telephony ranges 071xx-075xx, 07624 (Isle of Man) and 077xx-079xx;
//! 070 is personal numbering and 076 pagers - neither is a mobile.
//!
//! FP policy: 11-digit trunk-0 form, bare or separated; the second digit
//! class [1-57-9] excludes the 070 personal and 076 pager blocks (both
//! sources agree they are not mobiles; the 07624 Isle-of-Man exception
//! is deliberately not carved out). No cue (PHONE family, 0.8).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)07[1-57-9]\d(?:[ .-]?\d){7}(?!\d)",
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
        engine_detect(text, &["uk"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn uk_mobile_forms_detected() {
        // independent public metadata-set example number + spacing variants
        assert!(is_phone("call me on 07400 123456 please"));
        assert!(is_phone("call me on 07400123456 please"));
        assert!(is_phone("num 07911-123456 ok"));
        // negatives: 070 personal, 076 pager, wrong length
        assert!(!is_phone("line 070 1234566 here"));
        assert!(!is_phone("pager 076 1234566 here"));
        assert!(!is_phone("ref 0740012345 here"));
    }
}
