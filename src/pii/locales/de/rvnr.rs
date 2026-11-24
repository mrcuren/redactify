//! German pension insurance number (Versicherungsnummer of the statutory
//! pension insurance, "Rentenversicherungsnummer"): validator + rule.
//!
//! Official sources (retrieved 2026-10-30):
//! - Deutsche Rentenversicherung, "Gemeinsame Rechtliche Arbeitsanweisung
//!   (GRA) zu § 147 SGB VI: Versicherungsnummer", Stand 08.11.2024,
//!   <https://rvrecht.deutsche-rentenversicherung.de/SharedDocs/rvRecht/01_GRA_SGB/06_SGB_VI/pp_0126_150/gra_sgb006_p_0147.html>:
//!   serial numbers "00" to "49" (male) and "50" to "99" (female, diverse,
//!   no entry); "Sind bei einem Geburtsdatum sämtliche Seriennummern
//!   verbraucht, wird zum Geburtstag die Zahl "32" oder "64" addiert; ist
//!   der Geburtstag der Erste Tag eines Monats, ist auch die Addition der
//!   Zahl "96" ausnahmsweise zulässig." Check digit (§ 2 Abs. 6 VKVV):
//!   "Der Buchstabe in der neunten Stelle der Versicherungsnummer wird
//!   durch eine zweistellige Zahl ersetzt, die die Position des
//!   Buchstabens im deutschen Alphabet kennzeichnet. Die Ziffern der damit
//!   zwölfstelligen Nummer werden - an der ersten Stelle beginnend - mit
//!   den Faktoren 2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2 und 1 multipliziert. Von
//!   den Produkten werden die Quersummen gebildet. Die Quersummen werden
//!   addiert. Die Summe wird durch 10 dividiert. Der verbleibende Rest ist
//!   die Prüfziffer."
//! - Spitzenorganisationen der Sozialversicherung, "Gemeinsames
//!   Rundschreiben zum Meldeverfahren" (Stand 11.09.2025),
//!   <https://rvrecht.deutsche-rentenversicherung.de/SharedDocs/rvRecht/05_Normen_und_Vertraege/10_Rundschreiben_SpV/50_meldeverfahren/gem_rs_meldeverf.pdf>,
//!   section 3.1.1: "... so dass bei diesem Personenkreis die
//!   Geburtsdaten 01 00 XX bis 95 00 XX in der Versicherungsnummer
//!   erscheinen können. Bei vor 2005 vergebenen Versicherungsnummern ist
//!   auch die Tagesangabe 00 möglich."
//!
//! Layout (12 characters): area number (2 digits), birth date `TTMMJJ`,
//! the initial letter of the birth name, serial number (2 digits), check
//! digit. The validator accepts the day values the sources allow (00-31,
//! the day + 32 or + 64, and 97 = day 01 + 96) and months 00-12; the day
//! is not checked against the month length (the sources state no such
//! rule for the shifted values).
//!
//! The only published example (DRV glossary "65 170839 J 08 8") fails the
//! published algorithm (it yields check digit 1); the validator follows
//! the algorithm (the precedent of the BR CNPJ FAQ example).
//!
//! Cue policy: a single mod-10 check digit, so a cue is REQUIRED (score
//! 1.0). A leading cue counts when its END lies within the 18-character
//! cue window before the value (`pii::context`), so the 19- to
//! 25-character compounds "Rentenversicherungsnummer",
//! "Sozialversicherungsnummer" and "Versicherungsnummer" are listed in
//! full; their common tail `sicherungsnummer` stays as the catch-all for
//! the other "...versicherungsnummer" spellings.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, two_digits, ContextPolicy, Rule};

/// Cue words (lowercase): the full compounds first (the reported cue is
/// the first listed one that is found), then their common tail
/// `sicherungsnummer`.
pub(super) const CUES: &[&str] = &[
    "rentenversicherungsnummer",
    "sozialversicherungsnummer",
    "versicherungsnummer",
    "sicherungsnummer",
    "rvnr",
    "sv-nummer",
];

/// Day field values allowed by the sources: 00 (unknown, before 2005),
/// 01-31, the day + 32 (33-63), the day + 64 (65-95) and 97 (day 01 + 96).
const fn day_ok(d: u32) -> bool {
    matches!(d, 0..=31 | 33..=63 | 65..=95 | 97)
}

/// Returns `true` if `vsnr` is a valid German pension insurance number:
/// eight digits (area number + `TTMMJJ`), an uppercase letter, two serial
/// digits and the § 2 Abs. 6 VKVV check digit (letter replaced by its
/// two-digit alphabet position, weights 2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1,
/// digit sums of the products added, sum modulo 10). The day field must
/// be 00-31, shifted by 32 or 64, or 97; the month 00-12.
///
/// # Examples
/// ```
/// use redactify::valid_de_rvnr;
/// assert!(valid_de_rvnr("15070649C103"));
/// assert!(!valid_de_rvnr("15070649C104")); // check digit off
/// assert!(!valid_de_rvnr("15071349C107")); // month 13 (check digit fits)
/// assert!(!valid_de_rvnr("65170839J088")); // glossary example fails the algorithm
/// ```
#[must_use]
pub fn valid_de_rvnr(vsnr: &str) -> bool {
    let b = vsnr.as_bytes();
    if b.len() != 12
        || !b[..8].iter().all(u8::is_ascii_digit)
        || !b[8].is_ascii_uppercase()
        || !b[9..].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    if !day_ok(two_digits(&b[2..4])) || two_digits(&b[4..6]) > 12 {
        return false;
    }
    let pos = u32::from(b[8] - b'A') + 1;
    let digits = b[..8]
        .iter()
        .map(|&c| u32::from(c - b'0'))
        .chain([pos / 10, pos % 10])
        .chain(b[9..11].iter().map(|&c| u32::from(c - b'0')));
    let sum: u32 = digits
        .zip([2u32, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1])
        .map(|(d, w)| {
            let p = d * w;
            p / 10 + p % 10
        })
        .sum();
    sum % 10 == u32::from(b[11] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeRvnr,
        r"(?<![A-Za-z0-9])\d{8}[A-Z]\d{3}(?![A-Za-z0-9])",
        Some(valid_de_rvnr),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{day_ok, valid_de_rvnr, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn check_digit_math() {
        // 1 5 0 7 0 6 4 9 | C = 0 3 | 1 0 with weights 2 1 2 5 7 1 2 1 2 1 2 1:
        // digit sums 2+5+0+8+0+6+8+9+0+3+2+0 = 43 -> check digit 3
        assert!(valid_de_rvnr("15070649C103"));
        for d in (0..10).filter(|&d| d != 3) {
            assert!(!valid_de_rvnr(&format!("15070649C10{d}")));
        }
        // the DRV glossary example yields check digit 1 under the algorithm
        assert!(valid_de_rvnr("65170839J081"));
        assert!(!valid_de_rvnr("65170839J088"));
    }

    #[test]
    fn day_and_month_fields() {
        let allowed: Vec<u32> = (0..100).filter(|&d| day_ok(d)).collect();
        assert_eq!(allowed.len(), 32 + 31 + 31 + 1);
        for d in [32, 64, 96, 98, 99] {
            assert!(!day_ok(d), "{d}");
        }
        // checksum-valid values with a field outside the sources' ranges
        assert!(!valid_de_rvnr("15071349C107")); // month 13
        assert!(!valid_de_rvnr("15320649C102")); // day 32
                                                 // day 00, month 00 (before 2005 / unknown) and day 97 (01 + 96)
        assert!(valid_de_rvnr("15000049C109"));
        assert!(valid_de_rvnr("15970149C107"));
        assert!(!valid_de_rvnr("1507064C9103")); // letter misplaced
        assert!(!valid_de_rvnr("15070649c103")); // lowercase letter
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("Versicherungsnummer: 15070649C103", &["de"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DeRvnr);
        assert!(engine_detect("Paket 15070649C103 versandt", &["de"]).is_empty());
        for cue in CUES {
            let text = format!("{cue} 15070649C103");
            assert_eq!(engine_detect(&text, &["de"]).len(), 1, "{text}");
        }
    }
}
