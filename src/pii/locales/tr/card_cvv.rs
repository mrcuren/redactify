//! Card security code (CVV2 / CVC2 / CID): 3-4 digits + mandatory card cue.
//!
//! Format only (cue required): a 3-4 digit code without a checksum. PCI
//! DSS treats it as sensitive authentication data ("3.3.1.2 The card
//! verification code is not stored upon completion of the authorization
//! process", PCI DSS v4.0.1; the PCI SSC FAQ
//! <https://www.pcisecuritystandards.org/faqs/1280/>, retrieved
//! 2026-11-23, names the values CAV2, CVC2, CVV2 or CID). A bare 3-4
//! digit number is everywhere, so the rule claims one only next to a
//! card-code cue (`CVV`, `CVC`, `Kart güvenlik kodu`, `Güvenlik kodu
//! (CVV)`). A 6-digit one-time password after the same words is not
//! matched (length).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, token_rest, ContextPolicy, Rule};

/// Card-code cues (normalized: lowercase, `ı -> i`).
pub(super) const CUES: &[&str] = &[
    "cvv",
    "cvc",
    "cvv2",
    "cvc2",
    "güvenlik kod",
    "guvenlik kod",
    "security code",
    "card verification",
];

/// A token of 3 or 4 ASCII digits.
fn valid_cvv(s: &str) -> bool {
    (3..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    // the whole token around the digits (leftmost-first + greedy): a run
    // inside an e-mail, a URL or an alphanumeric token comes with its
    // letters and fails the validator, so it is never claimed on its own;
    // no boundary assertion (cost note in `super::address`)
    rule!(
        EntityType::CardCvv,
        concat!(token_rest!(), r"[0-9]{3,}", token_rest!()),
        Some(valid_cvv),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn codes(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::CardCvv)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn card_code_needs_its_cue() {
        assert_eq!(codes("Kart güvenlik kodu (CVV): 656\n"), vec!["656"]);
        assert_eq!(codes("CVV: 043"), vec!["043"]);
        assert_eq!(codes("güvenlik kodu ise 812'dir."), vec!["812"]);
        assert_eq!(codes("Amex CID / CVC: 1234"), vec!["1234"]);
        for text in [
            "Oda No: 407",
            "SMS güvenlik kodunuz: 482913",
            "Paket Sayısı: 1, Birim: 250 gr",
            "Yıl: 2024",
        ] {
            assert!(codes(text).is_empty(), "{text}: {:?}", codes(text));
        }
    }
}
