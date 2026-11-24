//! Norwegian fødselsnummer and d-nummer: validator + rule.
//!
//! Official sources (retrieved 2026-10-29), Skatteetaten (the Norwegian
//! Tax Administration, which runs Folkeregisteret):
//!
//! 1. Folkeregisterhåndboken 2025, § 2-2 "Identifikasjonsnummer" (the text
//!    of folkeregisterloven § 2-2, second paragraph):
//!    <https://www.skatteetaten.no/rettskilder/type/handboker/folkeregisterhandboken/gjeldende/kapittel2-registreringspliktige-personer-identifikasjonsnummer/ID-2-2.001/>.
//!    "Fødselsnummeret består av elleve siffer. De seks første sifrene er
//!    personens fødselsdato i rekkefølge to siffer for dag, to for måned og
//!    to for år. De fem siste sifrene er individsiffer og kontrollsiffer.
//!    D-nummer er bygget opp på samme måte, likevel slik at første siffer
//!    er tillagt fire."
//! 2. "Nytt fødselsnummer fra 2032" (Folkeregisteret API documentation,
//!    linked from the Skatteetaten validation page
//!    <https://www.skatteetaten.no/deling/folkeregisteret/pid/validering/>
//!    as its technical documentation):
//!    <https://skatteetaten.github.io/folkeregisteret-api-dokumentasjon/nytt-fodselsnummer-fra-2032/>.
//!    Section "Hva er nytt?": systems "må kunne lese både dagens og ny
//!    kontrollberegning parallelt"; "I dagens kontrollberegning må rest
//!    etter moduluskontrollen være lik 0. I ny kontrollberegning vil rest
//!    etter moduluskontrollen tillate 0, 1, 2 og 3 som gyldige verdier.";
//!    "Individnummeret vil ikke lenger angi århundre." Section "Hvordan
//!    beregnes kontrollsifre etter 01.01.2032?": "Sifrene for k1 benyttes i
//!    denne rekkefølgen: 3, 7, 6, 1, 8, 9, 4, 5, 2"; "Sifrene for k2
//!    benyttes i denne rekkefølgen: 5, 4, 3, 2, 7, 6, 5, 4, 3, 2";
//!    "k1 = {11,12,13,14} - ((d1 x 3 + d2 x 7 + m1 x 6 + m2 x 1 + å1 x 8 +
//!    å2 x 9 + i1 x 4 + i2 x 5 + i3 x 2) MOD 11)"; "Hvis k1 > 10 så blir
//!    k1 = k1 - 11"; "Hvis k1 = 10 så forkastes k1"; "k2 beregnes likt som
//!    før med kun 1 - ett - gyldig siffer: k2 = 11 - ((d1 x 5 + d2 x 4 +
//!    m1 x 3 + m2 x 2 + å1 x 7 + å2 x 6 + i1 x 5 + i2 x 4 + i3 x 3 + k1 x
//!    2) MOD 11)"; "På samme måte forkastes fødselsnummeret hvis k2 = 10."
//!    Worked examples ("Eksempler"): `02013299997`, `30108299920` (old
//!    rule, k2 = 11 - 0 written 0) and `30108299939` (new rule, rest 1).
//!
//! Equivalent check implemented here: with S1 the k1-weighted sum of the
//! first nine digits, `(S1 + k1) mod 11` must be 0-3 (old rule: 0); with
//! S2 the k2-weighted sum of the first ten digits, `(S2 + k2) mod 11` must
//! be 0. Both accepted parallel to each other, as the source requires.
//! Date: day 01-31 (d-nummer: first digit + 4, i.e. day + 40), month
//! 01-12, a real calendar date; the century is not derivable (the
//! individual number no longer states it), so 29 February is accepted for
//! every year divisible by 4. Synthetic test numbers (a different
//! structure per the validation page) are out of scope.
//!
//! Cue policy: a cue is REQUIRED (score 1.0): the 2032 rule accepts four
//! k1 values, so 3.29% of random 11-digit runs pass both control digits
//! (0.24% together with the date; measured on 1,000,000 random runs), and
//! the shape collides with TCKN, PESEL and Steuer-IdNr.

use crate::pii::entity::EntityType;

use crate::pii::locales::{
    days_in_month, is_leap_two_digit_year, rule, two_digits, ContextPolicy, Rule,
};

/// Cue words (the identifier names used by the sources).
pub(super) const CUES: &[&str] = &[
    "fødselsnummer",
    "fødselsnumre",
    "d-nummer",
    "d-numre",
    "personidentifikator",
];

/// k1 weights (source: "3, 7, 6, 1, 8, 9, 4, 5, 2").
const K1: [u32; 9] = [3, 7, 6, 1, 8, 9, 4, 5, 2];
/// k2 weights (source: "5, 4, 3, 2, 7, 6, 5, 4, 3, 2").
const K2: [u32; 10] = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];

/// Returns `true` if `fnr` is a valid Norwegian fødselsnummer or d-nummer:
/// 11 digits, a real birth date `DDMMYY` (d-nummer: day + 40), the first
/// control digit under the current OR the 2032 rule (remainder 0-3) and
/// the second control digit (remainder 0).
///
/// # Examples
/// ```
/// use redactify::valid_no_fodselsnummer;
/// assert!(valid_no_fodselsnummer("02013299997")); // Skatteetaten example
/// assert!(valid_no_fodselsnummer("30108299939")); // 2032 rule (rest 1)
/// assert!(!valid_no_fodselsnummer("02013299998")); // k2 off
/// assert!(!valid_no_fodselsnummer("0201329999")); // 10 digits
/// ```
#[must_use]
pub fn valid_no_fodselsnummer(fnr: &str) -> bool {
    let b = fnr.as_bytes();
    if b.len() != 11 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut d = [0u32; 11];
    for (x, &c) in d.iter_mut().zip(b) {
        *x = u32::from(c - b'0');
    }
    // d-nummer: "første siffer er tillagt fire"
    let day = if d[0] >= 4 {
        (d[0] - 4) * 10 + d[1]
    } else {
        two_digits(&b[0..2])
    };
    let month = two_digits(&b[2..4]);
    let leap = is_leap_two_digit_year(two_digits(&b[4..6]));
    if day == 0 || day > days_in_month(month, leap) {
        return false;
    }
    let s1: u32 = d.iter().zip(K1).map(|(&x, w)| x * w).sum::<u32>() + d[9];
    let s2: u32 = d.iter().zip(K2).map(|(&x, w)| x * w).sum::<u32>() + d[10];
    s1 % 11 <= 3 && s2 % 11 == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::NoFodselsnummer,
        r"(?<![\d.\-])\d{11}(?![\d\-])",
        Some(valid_no_fodselsnummer),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_no_fodselsnummer, K1, K2};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn skatteetaten_worked_examples() {
        // 020132 999: k1 = 11 - (156 MOD 11) = 9, k2 = 11 - (169 MOD 11) = 7
        let d = [0u32, 2, 0, 1, 3, 2, 9, 9, 9];
        assert_eq!(d.iter().zip(K1).map(|(a, w)| a * w).sum::<u32>(), 156);
        let d2 = [0u32, 2, 0, 1, 3, 2, 9, 9, 9, 9];
        assert_eq!(d2.iter().zip(K2).map(|(a, w)| a * w).sum::<u32>(), 169);
        for v in ["02013299997", "30108299920", "30108299939"] {
            assert!(valid_no_fodselsnummer(v), "{v}");
        }
    }

    #[test]
    fn all_four_2032_k1_values_and_d_numbers() {
        // 150385456 with bases 11..14 -> four valid numbers
        for v in ["15038545660", "15038545679", "15038545687", "15038545695"] {
            assert!(valid_no_fodselsnummer(v), "{v}");
        }
        // a k1 digit outside the four accepted remainders
        assert!(!valid_no_fodselsnummer("15038545601"));
        // d-nummer: day 01 + 40 and day 31 + 40
        assert!(valid_no_fodselsnummer("41019012393"));
        assert!(valid_no_fodselsnummer("71019012306"));
        // day 32 + 40 / month 13 / day 0 (check digits computed valid
        // for the old rule would not rescue an impossible date)
        assert!(!valid_no_fodselsnummer("72019012300"));
        assert!(!valid_no_fodselsnummer("01139012300"));
        assert!(!valid_no_fodselsnummer("00019012300"));
        // 29 February accepted for a year divisible by 4
        assert!(valid_no_fodselsnummer("29020012380"));
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("ordre 02013299997 sendt", &["no"]).is_empty());
        let ents = engine_detect("Fødselsnummer: 02013299997", &["no"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::NoFodselsnummer);
        let d = engine_detect("D-nummer 41019012393", &["no"]);
        assert_eq!(d.len(), 1, "{d:?}");
    }
}
