//! Turkish person names in **labeled contexts** (cue + capitalized sequence).
//!
//! Names carry no checksum, so this rule claims a capitalized sequence only
//! when a label cue ("ad soyad", "isim", "kimlik", "müşteri", ...) appears
//! within the context window (see [`crate::pii::context`]). It covers names
//! the lexicon does not hold ("Ad Soyad: Jean-Pierre Dupont"); names in free
//! prose are found by the label-free lexicon scanner [`super::person`], and
//! the optional NER layer (`ml-onnx`) adds model spans. All of them merge
//! through the same overlap resolution and lose to every checksum-validated
//! identifier.
//!
//! A capitalized label word never starts a candidate ("Müşteri Ahmet
//! Yılmaz aradı" claims "Ahmet Yılmaz", the label stays the cue), and a
//! candidate holding an organisation or address word ("Ahmet Yılmaz
//! Holding") is rejected.
//!
//! Limits (also listed in the README):
//! - 2-4 capitalized words: a lone first name after "İsim:" is left to
//!   [`super::person`] (which claims it after a name label).
//! - Each word must start with one uppercase letter followed by lowercase
//!   (`\p{Lu}\p{Ll}+`): all-caps surnames ("AHMET YILMAZ") and single-letter
//!   initials are not matched here.
//! - No apostrophe-joined suffixes: "Yılmaz'ın" keeps the name and drops the
//!   suffix (a permissive `'…` rule would swallow Turkish locatives like
//!   "İstanbul'da" into the name span).

use super::person_lexicon::{fold, lookup, Flags, MAX_KEY};
use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (already i-normalized for [`crate::pii::context`]) that make a
/// capitalized sequence claimable as a person name. Compound forms are chosen
/// deliberately: a bare "adi" cue would also fire inside unrelated words
/// (e.g. "tadilat", "tadil"). The context normalization folds only `ı` and
/// the combining dot, so "müşteri" is listed in its Turkish spelling next to
/// the ASCII "musteri" (with the ASCII form alone, "Müşteri: Ahmet Yılmaz"
/// finds nothing). There is no bare "adi:" cue: it would unlock the value
/// of any "X adı:" label ("Ürün adı: Sultan Çay", "Proje adı: ..."); a person's
/// "Adı:" field is claimed by [`super::person`], which tells person labels
/// ("Hasta adı:") from thing labels and masks the whole value.
pub(super) const CUES: &[&str] = &[
    "ad soyad",
    "adsoyad",
    "adi soyadi",
    "soyadi:",
    "isim",
    "kimlik",
    "musteri",
    "müşteri",
];

/// Label words: a candidate made up **entirely** of these is the label phrase
/// itself ("Adı Soyadı"), not a name - the validator rejects it. A candidate
/// that contains at least one non-label word ("Dr Ahmet Yılmaz") is kept.
const LABEL_WORDS: &[&str] = &[
    "ad",
    "soyad",
    "adi",
    "soyadi",
    "isim",
    "kimlik",
    "musteri",
    "müşteri",
    "unvan",
];

/// Rejects the label phrase itself (every word a label word, e.g. "Adı
/// Soyadı" inside "Kimlik Adı Soyadı: Ahmet Yılmaz"), organisation or
/// address names ("Ahmet Yılmaz Holding", "Fevzi Çakmak Caddesi"; the
/// organisation words of [`super::person_lexicon`]) and Title Case
/// phrases next to a cue word ("Kimlik Kartı Seri Numarası", "Müşteri
/// Hizmetleri Birimi"): a word that is a frequent Turkish word or a
/// proper noun rejects the candidate unless it is also a common name
/// ("Deniz Kaya" stays). On the nm-kvkk-pii-6K train split, with the
/// label word kept out of the candidate, such phrases make up most of the
/// rule's false positives without this filter.
fn plausible_name(candidate: &str) -> bool {
    let norm = crate::pii::context::normalize_tr(candidate);
    let label_only = norm
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .all(|w| LABEL_WORDS.contains(&w));
    let mut org_or_word = false;
    for w in candidate.split(|c: char| c.is_whitespace() || c == '-') {
        let mut buf = [0; MAX_KEY];
        let flags = fold(w, &mut buf).map_or_else(Flags::default, lookup);
        let common_name = flags.any(Flags::FIRST | Flags::LAST) && flags.has(Flags::COMMON);
        org_or_word |= flags.any(Flags::ORG)
            || (flags.any(Flags::FREQUENT_WORD | Flags::PROPER) && !common_name);
    }
    !label_only && !org_or_word
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Name,
        r"\b(?!(?:Ad|Adı|Soyad|Soyadı|İsim|Isim|Kimlik|Müşteri|Musteri|Unvan)\b)\p{Lu}\p{Ll}+(?:-\p{Lu}?\p{Ll}+)*(?:\s+\p{Lu}\p{Ll}+(?:-\p{Lu}?\p{Ll}+)*){1,3}\b",
        Some(plausible_name),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::detect::DetectionSource;
    use crate::pii::entity::EntityType;

    /// The names THIS rule reports (the label-free scanner `tr::person`
    /// runs in the same pass and is filtered out by its explanation).
    fn names(text: &str) -> Vec<(EntityType, String, f32)> {
        let out = crate::pii::run(
            text,
            &crate::pii::EngineOpts {
                locales: &["tr"],
                explain: true,
                ..crate::pii::EngineOpts::default()
            },
        );
        out.entities
            .into_iter()
            .zip(out.explanations)
            .filter(|(_, why)| why.source == DetectionSource::Rule { id: "tr::name" })
            .map(|(e, _)| (e.kind, e.text, e.score))
            .collect()
    }

    /// Every name of the engine pass (both name detectors).
    fn all_names(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::Name)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn turkish_spelling_of_the_customer_cue_unlocks_a_name() {
        // the ASCII cue "musteri" alone never matches the correctly
        // spelled "Müşteri" (context folding keeps ü and ş)
        for text in [
            "Müşteri: Ahmet Yılmaz",
            "müşteri Ahmet Yılmaz aradı",
            "MÜŞTERİ: Ahmet Yılmaz",
            "Musteri: Ahmet Yılmaz",
        ] {
            let found = names(text);
            assert!(
                found.contains(&(EntityType::Name, "Ahmet Yılmaz".into(), 0.85)),
                "{text:?}: {found:?}"
            );
        }
    }

    #[test]
    fn capitalized_label_word_is_not_swallowed_into_the_name() {
        // if the label joined the candidate, the cue would lie inside the
        // match and nothing would be claimed
        for text in [
            "Müşteri Ahmet Yılmaz aradı",
            "Musteri Ahmet Yılmaz aradı",
            "Müşteri Adı Ahmet Yılmaz",
        ] {
            let found = names(text);
            assert_eq!(
                found,
                [(EntityType::Name, "Ahmet Yılmaz".to_owned(), 0.85)],
                "{text:?}"
            );
        }
    }

    #[test]
    fn organisation_after_a_cue_is_not_a_name() {
        assert!(names("Müşteri: Ahmet Yılmaz Holding").is_empty());
        assert!(all_names("Müşteri: Ahmet Yılmaz Holding").is_empty());
        assert!(names("İsim: Fevzi Çakmak Caddesi").is_empty());
        // a label naming a thing is no name cue
        assert!(all_names("Ürün adı: Sultan Çay").is_empty());
    }

    #[test]
    fn title_case_phrase_next_to_a_cue_is_not_a_name() {
        assert!(names("Kimlik Kartı Seri Numarası: A12").is_empty());
        assert!(names("Müşteri Hizmetleri Birimi").is_empty());
        // common names that are also words still pass
        assert_eq!(
            names("Ad Soyad: Deniz Kaya"),
            [(EntityType::Name, "Deniz Kaya".to_owned(), 0.85)]
        );
    }

    #[test]
    fn free_prose_names_come_from_the_lexicon_scanner() {
        let text = "Bugün toplantıda Ahmet Yılmaz konuştu.";
        assert!(names(text).is_empty());
        assert_eq!(all_names(text), ["Ahmet Yılmaz"]);
        assert_eq!(all_names("AD SOYAD: AHMET YILMAZ"), ["AHMET YILMAZ"]);
    }

    #[test]
    fn labeled_full_name_detected() {
        let found = names("Ad Soyad: Ahmet Yılmaz, telefon 0532 123 45 67.");
        assert!(
            found.contains(&(EntityType::Name, "Ahmet Yılmaz".into(), 0.85)),
            "{found:?}"
        );
    }

    #[test]
    fn dotted_capital_i_label_works() {
        // 'İsim' lowercases to i + U+0307; the context normalization strips
        // the combining dot so the "isim" cue matches.
        let found = names("İsim: İsmail Özçelik arayacak.");
        assert!(
            found.contains(&(EntityType::Name, "İsmail Özçelik".into(), 0.85)),
            "{found:?}"
        );
    }

    #[test]
    fn no_cue_no_claim() {
        // Free prose without a label: precision-first, not claimed.
        assert!(names("Bugün toplantıda Ahmet Yılmaz konuştu.").is_empty());
    }

    #[test]
    fn turkish_suffix_apostrophe_not_swallowed() {
        let found = names("Adı Soyadı: Ahmet Yılmaz'ın telefonu 0212 555 44 33.");
        assert!(
            found.contains(&(EntityType::Name, "Ahmet Yılmaz".into(), 0.85)),
            "{found:?}"
        );
    }

    #[test]
    fn label_phrase_itself_is_rejected() {
        // The validator must reject "Adı Soyadı" (all label words) so only
        // the actual name is masked.
        let found = names("Müşteri Adı Soyadı: Ayşe Demir.");
        let texts: Vec<&str> = found.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(texts.contains(&"Ayşe Demir"), "{found:?}");
        assert!(
            !texts
                .iter()
                .any(|t| t.contains("Adı") || t.contains("Soyadı") || t.contains("Müşteri")),
            "{found:?}"
        );
    }

    #[test]
    fn two_names_in_one_line() {
        // Two labeled fields on one line: each name has its own cue in range
        // (the shared "Ad Soyad" cue is outside the 18-char window for the
        // second name, so the form carries a second label).
        let found = names("Ad Soyad: Ahmet Yılmaz, İsim: Ayşe Demir aynı masada.");
        let count = found
            .iter()
            .filter(|(k, _, _)| *k == EntityType::Name)
            .count();
        assert_eq!(count, 2, "{found:?}");
    }

    #[test]
    fn hyphenated_name_detected() {
        let found = names("Ad Soyad: Jean-Pierre Dupont.");
        assert!(
            found.contains(&(EntityType::Name, "Jean-Pierre Dupont".into(), 0.85)),
            "{found:?}"
        );
    }

    #[test]
    fn all_caps_not_matched() {
        // Documented limit: the word shape requires lowercase after the
        // initial capital.
        assert!(names("AD SOYAD: AHMET YILMAZ").is_empty());
    }

    #[test]
    fn cue_beyond_window_is_ignored() {
        // "isim" is more than 18 characters away from the candidate.
        assert!(
            names("Lütfen isim ile ilgili formu eksiksiz doldurunuz: Ahmet Yılmaz.").is_empty()
        );
    }

    #[test]
    fn threshold_drops_labeled_name() {
        // 0.85 < 0.9: a name-only text is dropped by the confidence cutoff.
        let ents = crate::pii::run(
            "Ad Soyad: Ahmet Yılmaz",
            &crate::pii::EngineOpts {
                threshold: 0.9,
                ..crate::pii::EngineOpts::default()
            },
        )
        .entities;
        assert!(ents.is_empty(), "{ents:?}");
    }
}
