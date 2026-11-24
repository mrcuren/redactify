//! MERSİS number (Central Registry System number of a trade-registered
//! business): 16 digits + mandatory cue.
//!
//! Source: Ministry of Trade, trade registry FAQ: "MERSİS'te verilen 16
//! haneli tekil ve benzersiz numara MERSİS numarasıdır", formed from the
//! TCKN for natural persons and from the tax number for legal persons
//! (<https://ticaret.gov.tr/ic-ticaret/sikca-sorulan-sorular/ticaret-sicili>,
//! retrieved 2026-11-23). No check-digit algorithm is published (none was
//! found in the FAQ or in the bank and accounting pages that describe the
//! number), so the rule is format only: 16 digits next to a `MERSİS` cue.
//! The overlap tier is the top tier: about one in ten 16-digit values
//! passes Luhn, and the cue-less card rule must not relabel a cued MERSİS
//! number. A top-tier span must never be a fragment of a larger entity,
//! so the pattern takes the whole token around the digits and the
//! validator wants exactly 16 digits: in `Mersis: x1234567890123456@firma.com`
//! the e-mail stays one entity instead of becoming `x[MERSIS]@firma.com`.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, token_rest, ContextPolicy, Rule};

/// MERSİS cues (normalized: lowercase, `ı -> i`; `İ` lowercases to `i`).
pub(super) const CUES: &[&str] = &["mersis"];

/// A token of exactly 16 ASCII digits.
fn valid_mersis(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    // the whole token around the digits (leftmost-first + greedy): a run
    // inside an e-mail, a URL or an alphanumeric token comes with its
    // letters and fails the validator, so it is never claimed on its own;
    // no boundary assertion (cost note in `super::address`)
    rule!(
        EntityType::Mersis,
        concat!(token_rest!(), r"[0-9]{16,}", token_rest!()),
        Some(valid_mersis),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn found(text: &str) -> Vec<(EntityType, String)> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .map(|e| (e.kind, e.text))
            .collect()
    }

    #[test]
    fn mersis_needs_its_cue_and_outranks_the_card_rule() {
        assert_eq!(
            found("Kurum MERSİS numarası: 0647064329700019\n"),
            vec![(EntityType::Mersis, "0647064329700019".to_owned())]
        );
        // a Luhn-valid 16-digit run: cued MERSİS, uncued card
        assert_eq!(
            found("MERSİS No: 4111111111111111"),
            vec![(EntityType::Mersis, "4111111111111111".to_owned())]
        );
        assert_eq!(
            found("Kart: 4111111111111111"),
            vec![(EntityType::CreditCard, "4111111111111111".to_owned())]
        );
        assert!(found("Referans: 0647064329700019").is_empty());
        // digits inside an e-mail stay part of the e-mail
        assert_eq!(
            found("Mersis: x1234567890123456@firma.com"),
            vec![(EntityType::Email, "x1234567890123456@firma.com".to_owned())]
        );
    }
}
