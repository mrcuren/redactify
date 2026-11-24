//! Customer number (müşteri numarası): 6-12 digits + mandatory cue.
//!
//! Format only (cue required): every company numbers its customers its
//! own way and no public standard or checksum exists, so a digit run is
//! claimed only next to a compound customer-number cue (`Müşteri No:`,
//! `müşteri numarası`, `müşteri kaydı`). The bare word `müşteri` is not a
//! cue: `Müşteri hizmetleri 2125550000` is a phone line, not a customer
//! number. A run that is also a valid TCKN keeps the TCKN label (higher
//! overlap tier).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, token_rest, ContextPolicy, Rule};

/// Customer-number cues (normalized: lowercase, `ı -> i`).
pub(super) const CUES: &[&str] = &[
    "müşteri no",
    "musteri no",
    "müşteri numara",
    "musteri numara",
    "müşteri kod",
    "musteri kod",
    "müşteri kayd",
    "musteri kayd",
    "müşteri kayit",
    "musteri kayit",
    // snake_case field names (`"musteri_numarasi": "066073625"`)
    "müşteri_no",
    "musteri_no",
    "customer_no",
    "customer_id",
    "müşteri referans",
    "musteri referans",
    "müşteri id",
    "musteri id",
    // trailing form: `1242994 numaralı müşteri kaydı`
    "numarali müşteri",
    "numarali musteri",
    "customer no",
    "customer number",
    "customer id",
];

/// A token of 6 to 12 ASCII digits.
fn valid_customer_number(s: &str) -> bool {
    (6..=12).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    // the whole token around the digits (leftmost-first + greedy): a run
    // inside an e-mail, a URL or an alphanumeric token comes with its
    // letters and fails the validator, so it is never claimed on its own;
    // no boundary assertion (cost note in `super::address`)
    rule!(
        EntityType::CustomerNumber,
        concat!(token_rest!(), r"[0-9]{6,}", token_rest!()),
        Some(valid_customer_number),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn numbers(text: &str) -> Vec<(EntityType, String)> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .map(|e| (e.kind, e.text))
            .collect()
    }

    #[test]
    fn customer_number_needs_a_compound_cue() {
        assert_eq!(
            numbers("Müşteri No: 1344536\n"),
            vec![(EntityType::CustomerNumber, "1344536".to_owned())]
        );
        assert_eq!(
            numbers("CRM kayıtlarında yer alan müşteri numarası 527313208 ve"),
            vec![(EntityType::CustomerNumber, "527313208".to_owned())]
        );
        assert_eq!(
            numbers("1242994 numaralı müşteri kaydını inceledik"),
            vec![(EntityType::CustomerNumber, "1242994".to_owned())]
        );
        for text in [
            "Müşteri hizmetleri 2125550000",
            "Sipariş No: 1234567",
            "Müşteri No: 12345",
        ] {
            assert!(
                !numbers(text)
                    .iter()
                    .any(|(k, _)| *k == EntityType::CustomerNumber),
                "{text}"
            );
        }
        // a valid TCKN keeps its own label
        assert_eq!(
            numbers("Müşteri No: 10000000146"),
            vec![(EntityType::Tckn, "10000000146".to_owned())]
        );
    }
}
