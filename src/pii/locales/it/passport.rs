//! Italian passport number: format validator + rule. FORMAT ONLY - the
//! source defines no check character.
//!
//! Official source (retrieved 2026-10-31): Decree of the Minister of
//! Foreign Affairs on the electronic passport, technical annex, Gazzetta
//! Ufficiale Serie generale of 19-05-2010 (codice redazionale 10A05685),
//! <https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticoloDefault/originario?atto.dataPubblicazioneGazzetta=2010-05-19&atto.codiceRedazionale=10A05685&atto.tipoProvvedimento=DECRETO>,
//! "Numero di serie del passaporto": "... ed e' composto da una sequenza
//! alfanumerica di due lettere indicanti tipologia e serie del
//! passaporto, seguite da sette numeri arabi."
//!
//! Cue policy: no checksum exists, so a cue is REQUIRED (score 0.9,
//! format + mandatory cue; passport precedent).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): the document's Italian and English names.
pub(super) const CUES: &[&str] = &["passaporto", "passport"];

/// Returns `true` if `number` has the Italian passport serial-number
/// format: two uppercase letters followed by seven digits.
///
/// # Examples
/// ```
/// use redactify::valid_it_passport;
/// assert!(valid_it_passport("YA1234567"));
/// assert!(!valid_it_passport("YA123456"));  // six digits
/// assert!(!valid_it_passport("Y12345678")); // one letter
/// assert!(!valid_it_passport("ya1234567")); // lowercase
/// ```
#[must_use]
pub fn valid_it_passport(number: &str) -> bool {
    let b = number.as_bytes();
    b.len() == 9
        && b[..2].iter().all(u8::is_ascii_uppercase)
        && b[2..].iter().all(u8::is_ascii_digit)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ItPassport,
        r"(?<![A-Za-z0-9])[A-Z]{2}\d{7}(?![A-Za-z0-9])",
        Some(valid_it_passport),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_it_passport;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure() {
        assert!(valid_it_passport("YA1234567"));
        assert!(valid_it_passport("AA0000000"));
        assert!(!valid_it_passport("YA12345678"));
        assert!(!valid_it_passport("YA12345B7"));
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("passaporto YA1234567 rilasciato", &["it"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::ItPassport);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
        assert!(engine_detect("pratica YA1234567 chiusa", &["it"]).is_empty());
        assert!(engine_detect("passport no. YA1234567", &["it"]).len() == 1);
    }
}
