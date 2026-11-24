//! Turkish vehicle plate: validator + detection rule (province + alphabet +
//! the regulation's letter/digit groups + cue boost).
//!
//! Official source (retrieved 2026-10-31): "Karayolları Trafik
//! Yönetmeliğinde Değişiklik Yapılmasına Dair Yönetmelik", Resmî Gazete
//! 19.02.2014, sayı 28918, Madde 9 (Karayolları Trafik Yönetmeliği madde
//! 55, birinci fıkra),
//! <https://www.resmigazete.gov.tr/eskiler/2014/02/20140219-8.htm>:
//! "Tescil plakalarında; il kod numarasından sonra ikili harf üçlü rakam,
//! tekli harf dörtlü rakam ve üçlü harf ikili rakam" followed by "ikili
//! harf dörtlü rakam, tekli harf beşli rakam ve üçlü harf üçlü rakam".
//! The amendment of RG 13.04.2016 does not change madde 55.
//!
//! The six letter/digit groups after the province code are therefore
//! exactly 2+3, 1+4, 3+2, 2+4, 1+5 and 3+3. The province range 01-81 and
//! the letter alphabet (no Q, W, X) are not stated in madde 55; the
//! validator checks them separately.

use fancy_regex::Regex;
use std::sync::LazyLock;

static PLAKA_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{2})\s?([A-PR-VY-Z]{1,3})\s?(\d{2,5})$")
        .expect("embedded plate pattern compiles")
});

/// (letters, digits) groups of KTY madde 55/1.
const GROUPS: [(usize, usize); 6] = [(2, 3), (1, 4), (3, 2), (2, 4), (1, 5), (3, 3)];

/// Returns `true` if `plate` is a valid Turkish plate.
///
/// Rules:
/// - province code 01-81 (`99 ABC 123` is invalid - there is no province 99),
/// - letters from the registration alphabet, **excluding Q/W/X**
///   (`[A-PR-VY-Z]`; C/G/I/O/S/U with diacritics are not used in
///   registration either),
/// - the letter/digit groups of KTY madde 55/1 only: 2 letters + 3
///   digits, 1 + 4, 3 + 2, 2 + 4, 1 + 5 or 3 + 3 (`34 A 12` and
///   `34 ABC 1234` are invalid),
/// - the separator is a space or a hyphen (`34 ABC 123`, `34-ABC-123`).
///
/// # Examples
/// ```
/// use redactify::valid_plaka;
/// assert!(valid_plaka("34 ABC 123"));
/// assert!(valid_plaka("34-ABC-123"));  // hyphenated form
/// assert!(valid_plaka("06 ank 06"));   // lowercase is uppercased
/// assert!(valid_plaka("34 A 12345"));  // 1 letter + 5 digits
/// assert!(!valid_plaka("99 ABC 123")); // no province 99
/// assert!(!valid_plaka("34 QWX 123")); // Q/W/X not in the plate alphabet
/// assert!(!valid_plaka("34 ABC 1234")); // 3 letters + 4 digits: not a KTY group
/// ```
#[must_use]
pub fn valid_plaka(plate: &str) -> bool {
    // Normalize the hyphenated form to the spaced one (34-ABC-123 -> 34 ABC 123).
    let up: String = plate
        .trim()
        .replace('-', " ")
        .chars()
        .flat_map(char::to_uppercase)
        .collect();
    match PLAKA_FULL.captures(&up) {
        Ok(Some(c)) => {
            let prov = c.get(1).map_or("", |m| m.as_str());
            let letters = c.get(2).map_or(0, |m| m.as_str().len());
            let digits = c.get(3).map_or(0, |m| m.as_str().len());
            matches!(prov.parse::<u8>(), Ok(p) if (1..=81).contains(&p))
                && GROUPS.contains(&(letters, digits))
        }
        _ => false,
    }
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// The cue words of both plate rules. The last two ("araç", vehicle, and
/// its ASCII spelling) only unlock a compact plate: the word stands in front of every cue-led compact
/// plate of the labelled fixtures ("Araç 06AB1234 servisteyken").
const COMPACT_CUES: &[&str] = &[
    "plaka",
    "arac plakasi",
    "plaka numarasi",
    "kayit plakasi",
    "tr plaka",
    "license plate",
    "number plate",
    "plate",
    "tasit plakasi",
    "kayit",
    "araç",
    "arac",
];

/// Cue words that boost plate confidence from 0.85 to 0.95: the plate cues
/// of [`COMPACT_CUES`] without the vehicle word.
pub(super) const CUES: &[&str] = COMPACT_CUES.split_at(COMPACT_CUES.len() - 2).0;

/// Plate rule. A specification list is not a plate: in `Laptop 16 GB 512
/// GB SSD` the shape `16 GB 512` is a valid plate (province 16, two
/// letters and three digits) but reads "16 GB, 512 GB". A candidate is
/// skipped only when BOTH its letter group is a unit of measure and a unit
/// follows its digits; one unit alone is a plate (`plaka 34 AB 123 KM`,
/// `34 KM 123`). The units: storage, frequency, mass, length, volume. `mAh` is left out: "Mah." (mahalle) follows
/// plates in Turkish addresses.
///
/// The separators are optional, so the compact uppercase form (`34ABC123`,
/// `06AB1234`) is claimed without a cue. In the labelled test sets every
/// compact plate stands next to a cue and the only cue-less compact
/// candidates are negative fixtures ("34ABC123 kodu depo etiketi"); a rare
/// false positive is preferred to an unmasked bare plate (leak-averse).
/// Lowercase letters (`34kk3058`) need a cue ([`compact_rule`]): a
/// lowercase run of digits and letters is more often an identifier or hash
/// fragment.
///
/// A province code written right after a standalone 1-2 digit number and
/// a slash or dot is the year of a date (`SKT 06/27 CVV 123`,
/// `12.06.27 AB 123`), not a plate: claiming it would hide the card expiry
/// and code under a plate label and leave the month in clear. A plate list
/// joined by slashes (`34 ABC 123/06 AB 1234`) keeps its second plate, as
/// a plate's serial ends in 2-5 digits after a letter or space.
///
/// The positive lookahead in front (two digits, an optional separator and
/// a plate letter) keeps the unit check off every other start position:
/// without it the pattern exhausts the backtrack budget on a
/// 200 000-character line of `12-` or `12.` (fancy-regex 0.20), and with
/// it the rule scans about 9% faster.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Plaka,
        r"(?<!\w)(?<!\W\d\d[/.])(?<!\W\d[/.])(?<!^\d\d[/.])(?<!^\d[/.])(?=\d{2}(?:\s|-)?[A-PR-VY-Z])(?!\d{2}(?:\s|-)?(?:[KMGTP]B|[KMG]HZ|KG|GR|KM|CM|MM|ML)(?:\s|-)?\d{2,5}\s?(?i:[kmgtp]b|[kmg]hz|kg|gr|km|cm|mm|ml)(?!\w))\d{2}(?:\s|-)?[A-PR-VY-Z]{1,3}(?:\s|-)?\d{2,5}(?!\w)",
        Some(valid_plaka),
        ContextPolicy::Boost(CUES, 0.95),
        0.85
    )
}

/// Compact plate with lowercase letters (`34kk3058`), only next to a plate
/// cue: the 3 lowercase compact plates of nm-kvkk-pii-6K stand next to
/// "Plaka:", "plakası" or "plakalı", and the cue-less lowercase candidates
/// of the labelled sets are negative fixtures ("34abc123 kodu girildi").
/// [`valid_plaka`] uppercases the letters. An uppercase compact plate is
/// claimed by [`rule`] already; this rule only adds the cue there.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn compact_rule() -> Rule {
    rule!(
        id = "tr::plaka_compact",
        EntityType::Plaka,
        r"(?<!\w)\d{2}[A-PR-VY-Za-pr-vy-z]{1,3}\d{2,5}(?!\w)",
        Some(valid_plaka),
        ContextPolicy::RequiredCue(COMPACT_CUES),
        0.95
    )
}

#[cfg(test)]
mod tests {
    use super::valid_plaka;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    fn plates(text: &str) -> Vec<String> {
        engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::Plaka)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn compact_plates() {
        for (text, want) in [
            ("Plaka: 34kk3058", "34kk3058"),
            ("Araç plakası: 34yu643", "34yu643"),
            ("Araç 34czy444 plakalı", "34czy444"),
            ("Araç 06AB1234 servisteyken", "06AB1234"),
        ] {
            assert_eq!(plates(text), [want], "{text}");
        }
        // uppercase compact plates are claimed without a cue (rule doc)
        for text in [
            "06AB1234",
            "Otomobil 34ABC123 trafikte",
            "34ABC123 numaralı",
        ] {
            assert_eq!(plates(text).len(), 1, "{text}");
        }
        // lowercase compact plates need one
        assert!(plates("34abc123 kodu girildi.").is_empty());
        // units of measure stay out, compact or not
        assert!(plates("Laptop 16GB512GB").is_empty());
        // separated forms stay cue-less
        assert_eq!(plates("34 ABC 123 otoparkta"), ["34 ABC 123"]);
        assert_eq!(plates("34ABC 123 otoparkta"), ["34ABC 123"]);
        assert_eq!(plates("34-ABC-123 otoparkta"), ["34-ABC-123"]);
    }

    #[test]
    fn the_vehicle_word_unlocks_only_a_compact_plate() {
        assert_eq!(super::CUES.len() + 2, super::COMPACT_CUES.len());
        assert!(super::CUES.contains(&"kayit"));
        assert!(!super::CUES.contains(&"araç") && !super::CUES.contains(&"arac"));
    }

    #[test]
    fn the_year_of_a_date_is_not_a_province_code() {
        for text in [
            "SKT 06/27 CVV 123",
            "06/27 CVV 123",
            "Son kullanma tarihi 6/29 CVV 456",
            "tarih 12.06.27 AB 123",
        ] {
            assert!(plates(text).is_empty(), "{text}");
        }
        // plates joined by a slash or after a long number keep their label
        assert_eq!(
            plates("Plaka 34 ABC 123/06 AB 1234"),
            ["34 ABC 123", "06 AB 1234"]
        );
        assert_eq!(
            plates("Plakalar: 34ABC123/34DEF456"),
            ["34ABC123", "34DEF456"]
        );
        assert_eq!(plates("Kayıt 2024/34 ABC 123"), ["34 ABC 123"]);
        assert_eq!(plates("Plaka: 34 CVV 123"), ["34 CVV 123"]);
    }

    #[test]
    fn long_hostile_lines_complete_within_the_backtrack_budget() {
        for r in [super::rule(), super::compact_rule()] {
            for unit in [
                "1", "1 ", "12A", "12 A ", "12.", "12-", "34AB", "a", "1/", "12/34 A ",
            ] {
                let text = unit.repeat(200_000 / unit.len());
                assert!(
                    r.regex.find_iter(&text).all(|m| m.is_ok()),
                    "{} on {unit:?}",
                    r.id
                );
            }
        }
    }

    #[test]
    fn golden_vectors() {
        assert!(valid_plaka("34 ABC 123"));
        assert!(valid_plaka("34-ABC-123")); // hyphenated form
        assert!(valid_plaka("06 ANK 06"));
        assert!(valid_plaka("06 AA 9999")); // 2 letters + 4 digits
        assert!(valid_plaka("06 A 99999")); // 1 letter + 5 digits: upper bound
        assert!(valid_plaka(" 06 ank 06 ")); // trim + uppercase
        assert!(!valid_plaka("99 ABC 123")); // no province 99
        assert!(!valid_plaka("00 ABC 123")); // no province 00
        assert!(!valid_plaka("34 ABC 1")); // serial needs at least 2 digits
        assert!(!valid_plaka("34 ABC 12345")); // 3 letters + 5 digits: not a KTY group
        assert!(!valid_plaka("34 A 123456")); // six digits
        assert!(!valid_plaka("34 QWX 123")); // Q/W/X not in the registration alphabet
        assert!(!valid_plaka("34 ÇĞŞ 123")); // diacritic letters not in the registration alphabet
        assert!(!valid_plaka(""));
        assert!(!valid_plaka("34 ABC 123 X"));
    }

    #[test]
    fn exactly_the_kty_55_groups() {
        // every (letters, digits) combination the pattern can produce:
        // only the six KTY madde 55/1 groups are valid
        let kty = [(2, 3), (1, 4), (3, 2), (2, 4), (1, 5), (3, 3)];
        for letters in 1..=3 {
            for digits in 2..=5 {
                let plate = format!(
                    "34 {} {}",
                    "ABC".get(..letters).unwrap(),
                    "12345".get(..digits).unwrap()
                );
                assert_eq!(
                    valid_plaka(&plate),
                    kty.contains(&(letters, digits)),
                    "{plate}"
                );
            }
        }
    }
}
