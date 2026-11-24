//! German lifelong physician number (Lebenslange Arztnummer, LANR):
//! validator + rule.
//!
//! Official sources (retrieved 2026-10-30):
//! - Kassenärztliche Bundesvereinigung, "Richtlinie der Kassenärztlichen
//!   Bundesvereinigung nach § 75 Absatz 7 SGB V zur Vergabe der Arzt-,
//!   Betriebsstätten-, Praxisnetz- sowie der Netzverbundnummern"
//!   (Stand 1. Januar 2024),
//!   <https://www.kbv.de/documents/infothek/rechtsquellen/weitere-vertraege/praxen/arzt-und-betriebsstaettennummer/Arztnummern_Richtlinie.pdf>,
//!   § 2 Abs. 1: "Die Arztnummer setzt sich aus insgesamt neun Ziffern
//!   zusammen: 1. einer sechsstelligen eineindeutigen Ziffernfolge
//!   (Ziffern 1 - 6) 2. einer Prüfziffer (Ziffer 7) 3. einem
//!   zweistelligen Arztgruppenschlüssel ... (Ziffern 8 - 9)".
//! - "Vereinbarung gemäß § 293 Absätze 4 und 7 SGB V über eine zentrale
//!   Arztnummernvergabe (Vereinbarung ANRV)" of 17.10.2018,
//!   <https://www.kbv.de/documents/infothek/rechtsquellen/weitere-vertraege/praxen/arzt-und-betriebsstaettennummer/ANRV-Vereinbarung.pdf>,
//!   § 4 Abs. 3: "Die Prüfziffer wird mittels Modulo-10-Verfahren der
//!   Stellen 1-6 der Arztnummer ermittelt. Bei diesem Verfahren werden die
//!   Ziffern 1-6 von links nach rechts abwechselnd mit 4 und 9
//!   multipliziert. Die Summe dieser Produkte wird Modulo 10 berechnet.
//!   Die Prüfziffer ergibt sich aus der Differenz dieser Zahl zu 10 (ist
//!   die Differenz 10, so ist die Prüfziffer 0)."
//! - KBV "Datensatzbeschreibung KVDT", Version 6.06 of 8 July 2026,
//!   <https://update.kbv.de/ita-update/Vorquartale/ita_update_2026_Q3/Abrechnung/KBV_ITA_VGEX_Datensatzbeschreibung_KVDT.pdf>,
//!   rule 050: LANR `nnnnnnmff` with "nnnnnn ungleich 555555" (the
//!   pseudo physician number).
//!
//! No official example number is published; the test vectors are
//! computed from ANRV § 4 Abs. 3.
//!
//! Cue policy: a single mod-10 check digit admits about 10% of random
//! 9-digit runs, so a cue is REQUIRED (score 1.0). The rule is registered
//! before the checksum-less Betriebsstättennummer rule (same 9-digit
//! shape): on an equal span the checksummed LANR claim wins.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): the identifier's names and abbreviations.
pub(super) const CUES: &[&str] = &["lanr", "arztnummer", "arzt-nr"];

/// Returns `true` if `lanr` is a valid LANR: nine ASCII digits whose
/// seventh digit is the ANRV § 4 Abs. 3 check digit over digits 1-6
/// (weights 4, 9, 4, 9, 4, 9; check = (10 - sum mod 10) mod 10). The
/// pseudo physician number (digits 1-6 = `555555`, KVDT rule 050) is
/// rejected.
///
/// # Examples
/// ```
/// use redactify::valid_de_lanr;
/// assert!(valid_de_lanr("123456601")); // 123456 -> check digit 6
/// assert!(!valid_de_lanr("123456701")); // check digit off
/// assert!(!valid_de_lanr("555555500")); // pseudo LANR
/// assert!(!valid_de_lanr("12345660"));  // 8 digits
/// ```
#[must_use]
pub fn valid_de_lanr(lanr: &str) -> bool {
    let b = lanr.as_bytes();
    if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if &b[..6] == b"555555" {
        return false;
    }
    let sum: u32 = b[..6]
        .iter()
        .zip([4u32, 9, 4, 9, 4, 9])
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    (10 - sum % 10) % 10 == u32::from(b[6] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeLanr,
        r"(?<!\d)\d{9}(?!\d)",
        Some(valid_de_lanr),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_de_lanr, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn check_digit_math() {
        // check digits computed by hand from ANRV § 4 Abs. 3:
        // 123456 -> 4+18+12+36+20+54 = 144 -> 6; 100000 -> 4 -> 6;
        // 987654 -> 36+72+28+54+20+36 = 246 -> 4
        for v in ["123456601", "100000601", "987654400", "987654499"] {
            assert!(valid_de_lanr(v), "{v}");
        }
        // remainder 0 -> check digit 0 (000000 -> sum 0)
        assert!(valid_de_lanr("000000012"));
        assert!(!valid_de_lanr("123456701"));
        assert!(!valid_de_lanr("555555500"));
        assert!(!valid_de_lanr("1234566011"));
        assert!(!valid_de_lanr("12345660A"));
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("LANR 123456601 eingetragen", &["de"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DeLanr);
        assert!(engine_detect("Auftrag 123456601 eingetragen", &["de"]).is_empty());
        for cue in CUES {
            let text = format!("{cue}: 987654400");
            assert_eq!(engine_detect(&text, &["de"]).len(), 1, "{text}");
        }
    }
}
