//! German vehicle registration plate (Kfz-Kennzeichen): format validator +
//! rule. FORMAT ONLY - the regulation defines no check character.
//!
//! Official source (retrieved 2026-10-30): "Verordnung zum Neuerlass der
//! Fahrzeug-Zulassungsverordnung und zur Änderung weiterer Vorschriften",
//! BGBl. 2023 I Nr. 199 of 28.07.2023,
//! <https://www.recht.bund.de/bgbl/1/2023/199/regelungstext.pdf?__blob=publicationFile&v=1>
//! (BGBl. 2025 I Nr. 382 amends only § 9 Abs. 3, not the parts used here).
//!
//! - FZV § 9 Abs. 1: "Das Kennzeichen hat zu bestehen aus 1. einem
//!   Unterscheidungszeichen mit ein bis drei Buchstaben für den
//!   Verwaltungsbezirk, in dem das Fahrzeug zugelassen ist, und 2. einer
//!   auf das einzelne Fahrzeug bezogenen Erkennungsnummer."
//! - Anlage 1 Nr. 1: "Mit Ausnahme der Umlaute Ä, Ö und Ü können alle
//!   übrigen Buchstaben des Alphabets jeweils entweder allein oder als
//!   Kombination von zwei Buchstaben in der Erkennungsnummer zugeteilt
//!   werden." Nr. 2: "A 1 - A 999", "AA 1 - AA 99", "AA 100 - AA 999",
//!   "A 1000 - A 9999", "AA 1000 - AA 9999" (each up to Z / ZZ).
//! - Anlage 4 Nr. 4: "Mehr als acht Stellen (Buchstaben und Ziffern) auf
//!   einem Kennzeichen sind unzulässig."
//! - § 10 Abs. 1 / § 11 Abs. 2: the official suffixes "H" and "E" "hinter
//!   der Erkennungsnummer".
//!
//! Accepted form: 1-3 letters (umlauts allowed: the Anlage 1 ban covers
//! only the Erkennungsnummer), a space or hyphen, 1-2 letters `A`-`Z`, an
//! optional space or hyphen, 1-4 digits without a leading zero (the
//! Anlage 1 ranges start at 1) and an optional `E` / `H` suffix; at most
//! eight letters and digits (suffix not counted). The list of assigned
//! Unterscheidungszeichen is not checked.
//!
//! Cue policy: no checksum exists, so a cue is REQUIRED (score 0.9,
//! format + mandatory cue). Broad prose words ("Auto", "Fahrzeug", "Pkw")
//! are deliberately not cues.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): the plate's names and the registration term.
pub(super) const CUES: &[&str] = &["kennzeichen", "kfz", "nummernschild", "zulassung"];

/// Returns `true` if `plate` has the German registration plate format:
/// an Unterscheidungszeichen of 1-3 uppercase letters (`Ä`, `Ö`, `Ü`
/// allowed), a space or hyphen, an Erkennungsnummer of 1-2 letters `A`-`Z`
/// and 1-4 digits (first digit 1-9, optional space or hyphen before the
/// digits), an optional `E` or `H` suffix, and at most eight letters and
/// digits in total (suffix excluded).
///
/// # Examples
/// ```
/// use redactify::valid_de_kfz;
/// assert!(valid_de_kfz("B AB 1234"));
/// assert!(valid_de_kfz("TÜ-A 12E"));
/// assert!(!valid_de_kfz("B AB 01"));      // leading zero
/// assert!(!valid_de_kfz("ABC DE 1234"));  // nine letters and digits
/// assert!(!valid_de_kfz("B ÄB 12"));      // umlaut in the Erkennungsnummer
/// ```
#[must_use]
pub fn valid_de_kfz(plate: &str) -> bool {
    let chars: Vec<char> = plate.chars().collect();
    let is_district = |c: char| c.is_ascii_uppercase() || matches!(c, 'Ä' | 'Ö' | 'Ü');
    let sep = |c: char| c == ' ' || c == '-';
    let mut i = 0;
    let take = |i: &mut usize, max: usize, pred: &dyn Fn(char) -> bool| -> usize {
        let start = *i;
        while *i < chars.len() && *i - start < max && pred(chars[*i]) {
            *i += 1;
        }
        *i - start
    };
    let district = take(&mut i, 3, &is_district);
    if district == 0 || i >= chars.len() || !sep(chars[i]) {
        return false;
    }
    i += 1;
    let letters = take(&mut i, 2, &|c: char| c.is_ascii_uppercase());
    if letters == 0 {
        return false;
    }
    if i < chars.len() && sep(chars[i]) {
        i += 1;
    }
    if i >= chars.len() || !matches!(chars[i], '1'..='9') {
        return false;
    }
    let digits = take(&mut i, 4, &|c: char| c.is_ascii_digit());
    if i < chars.len() && matches!(chars[i], 'E' | 'H') {
        i += 1;
    }
    i == chars.len() && district + letters + digits <= 8
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeKfz,
        r"(?<![\w-])[A-ZÄÖÜ]{1,3}[ -][A-Z]{1,2}[ -]?[1-9]\d{0,3}[EH]?(?![\w-])",
        Some(valid_de_kfz),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_de_kfz, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure() {
        for v in [
            "B AB 1234",
            "HH-A 1",
            "M-XY 999",
            "KA EF 1H",
            "TÜ-A 12E",
            "B-AB1234",
            "AB CD 1234", // exactly eight letters and digits
        ] {
            assert!(valid_de_kfz(v), "{v}");
        }
        for v in [
            "B AB 01",     // leading zero
            "ABC DE 1234", // nine letters and digits
            "B ÄB 12",     // umlaut in the Erkennungsnummer
            "B ABC 12",    // three letters in the Erkennungsnummer
            "B AB 12345",  // five digits
            "BAB 123",     // no separator after the district
            "B AB",        // no digits
            "b ab 12",     // lowercase
            "B AB 12X",    // suffix other than E / H
            "ABCD E 1",    // four-letter district
        ] {
            assert!(!valid_de_kfz(v), "{v}");
        }
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("Kennzeichen B AB 1234 gemeldet", &["de"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DeKfz);
        assert_eq!(ents[0].text, "B AB 1234");
        assert!(engine_detect("Raum B AB 1234 belegt", &["de"]).is_empty());
        for cue in CUES {
            let text = format!("{cue}: M-XY 999");
            assert_eq!(engine_detect(&text, &["de"]).len(), 1, "{text}");
        }
        // the nine-character shape matches the pattern but fails the
        // eight-position limit
        assert!(engine_detect("Kennzeichen ABC DE 1234", &["de"]).is_empty());
    }
}
