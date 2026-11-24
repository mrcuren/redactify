//! Italian numeric codice fiscale (11 digits, the tax code of subjects
//! other than natural persons): validator + rule. Reported as
//! `IT_FISCAL_CODE`, like the 16-character form of natural persons.
//!
//! Official sources:
//! - Decreto ministeriale 23 dicembre 1976 (n. 13813), "Sistemi di
//!   codificazione dei soggetti da iscrivere all'anagrafe tributaria",
//!   Gazzetta Ufficiale n. 345 of 29 December 1976, Supplemento ordinario
//!   (retrieved 2026-10-30),
//!   <https://www.gazzettaufficiale.it/eli/gu/1976/12/29/345/so/0/sg/pdf>.
//!   Art. 8: "Il numero di codice fiscale dei soggetti diversi dalle
//!   persone fisiche è costituito da una espressione numerica di undici
//!   cifre. Le prime sette cifre rappresentano il numero di matricola ...
//!   Le tre cifre dall'ottava alla decima rappresentano il codice
//!   identificativo della provincia ... L'undicesimo carattere ha funzione
//!   di controllo". Art. 9: "si sommano i valori di ciascuna delle cinque
//!   cifre di ordine dispari, partendo da sinistra; si raddoppia ogni
//!   cifra di ordine pari e, se il risultato è un numero di due cifre,
//!   esso si riduce ad una sola sommando la cifra relativa alle decine e
//!   quella relativa alle unità; si sommano quindi tutti i precedenti
//!   risultati; si determina il totale delle due somme di cui sopra; si
//!   sottrae da dieci la cifra relativa alle unità del precedente totale.
//!   Il carattere di controllo è la cifra relativa alle unità del
//!   risultato."
//! - Agenzia delle Entrate, "Codice fiscale per i soggetti diversi dalle
//!   persone fisiche (modello AA5/6) - Che cos'è" (retrieved 2026-10-31),
//!   <https://www.agenziaentrate.gov.it/portale/schede/istanze/codice-fiscale-modello-aa5_6/scheda-info-cf-aa5_6>:
//!   "Il codice fiscale dei soggetti diversi dalle persone fisiche è
//!   formato da 11 caratteri numerici ... l'ultimo è un carattere di
//!   controllo."
//!
//! The provincial office code (digits 8-10) is not checked (no list in
//! the sources). The all-zero value passes the check digit and is
//! rejected. No official example number is published; the test vectors
//! are computed from Art. 9.
//!
//! Cue policy: a single check digit admits about 10% of random 11-digit
//! runs, so a cue is REQUIRED (score 1.0). Only codice-fiscale cues are
//! used: no retrieved official text states that the partita IVA carries
//! the Art. 9 check digit (the `IT`-prefixed VAT form stays with the `eu`
//! pack).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): the identifier's name and its abbreviation.
pub(super) const CUES: &[&str] = &["codice fiscale", "c.f."];

/// Returns `true` if `cf` is a valid numeric codice fiscale: eleven ASCII
/// digits, not all zero, whose eleventh digit is the DM 13813 Art. 9
/// check digit (odd-position digits summed, even-position digits doubled
/// and reduced to one digit, check = (10 - total mod 10) mod 10).
///
/// # Examples
/// ```
/// use redactify::valid_it_numeric_fiscal_code;
/// assert!(valid_it_numeric_fiscal_code("12345678903"));
/// assert!(!valid_it_numeric_fiscal_code("12345678904")); // check digit off
/// assert!(!valid_it_numeric_fiscal_code("00000000000")); // all zero
/// assert!(!valid_it_numeric_fiscal_code("1234567890"));  // 10 digits
/// ```
#[must_use]
pub fn valid_it_numeric_fiscal_code(cf: &str) -> bool {
    let b = cf.as_bytes();
    if b.len() != 11 || !b.iter().all(u8::is_ascii_digit) || b.iter().all(|&c| c == b'0') {
        return false;
    }
    let total: u32 = b[..10]
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            let d = u32::from(c - b'0');
            // i is 0-based: even i = odd order (1st, 3rd, ...)
            if i % 2 == 0 {
                d
            } else {
                let x = d * 2;
                x / 10 + x % 10
            }
        })
        .sum();
    (10 - total % 10) % 10 == u32::from(b[10] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ItFiscalCode,
        r"(?<!\d)\d{11}(?!\d)",
        Some(valid_it_numeric_fiscal_code),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_it_numeric_fiscal_code;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn check_digit_math() {
        // 1234567890: odd 1+3+5+7+9 = 25, even 2,4,6,8,0 doubled -> 4+8+3+7+0
        // = 22, total 47 -> 10 - 7 = 3
        assert!(valid_it_numeric_fiscal_code("12345678903"));
        // 0123456789: odd 0+2+4+6+8 = 20, even 1,3,5,7,9 doubled -> 2+6+1+5+9
        // = 23, total 43 -> 7
        assert!(valid_it_numeric_fiscal_code("01234567897"));
        for d in (0..10).filter(|&d| d != 3) {
            assert!(!valid_it_numeric_fiscal_code(&format!("1234567890{d}")));
        }
        assert!(!valid_it_numeric_fiscal_code("00000000000"));
        assert!(!valid_it_numeric_fiscal_code("123456789031"));
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("codice fiscale 01234567897 della societa", &["it"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::ItFiscalCode);
        assert_eq!(
            engine_detect("C.F. 12345678903", &["it"])[0].kind,
            EntityType::ItFiscalCode
        );
        assert!(engine_detect("ordine 12345678903 spedito", &["it"]).is_empty());
    }
}
