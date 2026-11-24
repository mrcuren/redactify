//! Portuguese mobile phone number: detection rule (structural
//! pattern, no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public phone-number metadata set (PT mobile): NSN 9
//! digits `9(?:[1-36]\d\d|480)\d{5}`; example "912 345 678".
//! Wikipedia "Telephone numbers in Portugal": closed nine-digit
//! numbering with no trunk prefix; mobiles are 9T + 7 digits with
//! T in {0,1,2,3,6} at introduction (the current assigned mobile blocks
//! per the metadata set are 91/92/93/96), written 9xx xxx xxx.
//!
//! FP policy (TR-landline precedent): a SEPARATOR-BEARING 3-3-3 form is
//! required - a bare 9-digit run is never a Portuguese mobile, keeping
//! bare BSN/NIF/order-number shapes unclaimed. The spaced 3-3-3 shape
//! collides with the NIF rule's spaced form, so PT_NIF sits in the
//! checksum-over-structural priority tier (see `EntityType::priority`).
//! No cue (PHONE family, 0.8).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)9[1-36]\d[ .-]\d{3}[ .-]\d{3}(?!\d)",
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
        engine_detect(text, &["pt"])
            .iter()
            .any(|e| e.kind == EntityType::Phone)
    }

    #[test]
    fn portuguese_mobile_forms_detected() {
        // independent public metadata-set example number + spacing variants
        assert!(is_phone("telefona para 912 345 678 ok"));
        assert!(is_phone("num 963 123 456 ok"));
        assert!(is_phone("num 912-345-678 ok"));
        // negatives: bare runs never claimed; non-mobile 9-blocks
        assert!(!is_phone("ref 912345678 aqui"));
        assert!(!is_phone("linha 950 123 456 la")); // 95 not assigned
        assert!(!is_phone("fixo 212 345 678 la")); // 2x geographic
    }
}
