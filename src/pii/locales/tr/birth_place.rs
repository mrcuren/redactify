//! Place of birth: a Turkish province or district + mandatory birth cue.
//!
//! The value must be a gazetteer name ([`super::gazetteer`]: the 81
//! provinces and 973 districts of the `turkiye-api` datasets), written
//! with an uppercase first letter (`Kütahya`, `İSTANBUL`, `Izmir`). A
//! place name alone is not personal data, so the rule claims it only next
//! to a birth-place cue: `Doğum yeri: Bursa`, `Kayseri doğumlu oyuncu`.
//! A foreign or village birthplace is not detected (gazetteer coverage).
//!
//! The pattern takes every whole capitalized word (and `19 Mayıs`, the
//! one district name with a digit), and the allocation-free validator
//! [`is_place`] keeps only whole gazetteer names (`Ankaralı` is
//! rejected). No look-around and no word-boundary assertion, so the regex
//! engine stays on its DFA path on Turkish text (engine cost note in
//! [`super::address`]). On the 602 `nm-kvkk-pii-6K` test documents,
//! scanning with the ~1,000-name alternation itself costs 410 ms per
//! pass; this pattern plus the validator is the cheap form.

use crate::pii::entity::EntityType;

use super::gazetteer::is_place;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Birth-place cues (normalized: lowercase, `ı -> i`).
pub(super) const CUES: &[&str] = &[
    "doğum yer",
    "dogum yer",
    "doğum ili",
    "dogum ili",
    "doğduğu yer",
    "dogdugu yer",
    "doğduğu il",
    "dogdugu il",
    "doğumlu",
    "dogumlu",
    "d. yeri",
    "d.yeri",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::PlaceOfBirth,
        r"\p{Lu}[\p{L}\p{M}]*|19\s+(?:[Mm]ay[ıi]s|MAYIS)",
        Some(is_place),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn places(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::PlaceOfBirth)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn birth_place_needs_its_cue() {
        assert_eq!(places("Doğum yeri: Kütahya\n"), vec!["Kütahya"]);
        assert_eq!(places("DOĞUM YERİ: İSTANBUL"), vec!["İSTANBUL"]);
        assert_eq!(
            places("Kayseri doğumlu oyuncu maçı kazandırdı."),
            vec!["Kayseri"]
        );
        assert_eq!(
            places("Rabia Akar’ın Bursa doğumlu olduğu yazıyor."),
            vec!["Bursa"]
        );
        for text in [
            "Toplantı Ankara'da yapıldı.",
            "Doğum yeri: Berlin",
            "Teslimat ili: Aydın",
            "Doğum yeri: Ankaralı bir aile",
        ] {
            assert!(places(text).is_empty(), "{text}: {:?}", places(text));
        }
    }
}
