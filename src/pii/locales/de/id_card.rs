//! German identity card (Personalausweis) serial number: format validator
//! + rule. FORMAT ONLY - the serial number contains no check digit.
//!
//! Official sources (retrieved 2026-10-30):
//! - Deutscher Bundestag, BT-Drucksache 16/10489 of 07.10.2008,
//!   "Gesetzentwurf der Bundesregierung: Entwurf eines Gesetzes über
//!   Personalausweise und den elektronischen Identitätsnachweis",
//!   <https://dserver.bundestag.de/btd/16/104/1610489.pdf>, Art. 1, § 2
//!   Abs. 8 PAuswG-E: "Jeder Ausweis erhält eine neue Seriennummer. Die
//!   Seriennummer eines Personalausweises setzt sich aus einer
//!   vierstelligen Behördenkennzahl und einer fünfstelligen, zufällig
//!   vergebenen Nummer zusammen und kann Ziffern und Buchstaben enthalten.
//!   Die Seriennummer des vorläufigen Personalausweises besteht aus einem
//!   Buchstaben und sieben Ziffern." Abs. 9: "Die Prüfziffern werden aus
//!   den Daten des maschinenlesbaren Bereichs errechnet". (The
//!   consolidated PAuswG text was not reachable; the same sentence is
//!   quoted as the current § 2.)
//! - ICAO Doc 9303 "Machine Readable Travel Documents", Part 5 (TD1),
//!   Eighth Edition 2021,
//!   <https://www.icao.int/sites/default/files/publications/DocSeries/9303_p5_cons_en.pdf>,
//!   4.2.2 upper MRZ line: document number in positions 6 to 14, its
//!   check digit in position 15 ("Document number check digit: character
//!   positions used to calculate check digit 6 - 14; check digit position
//!   15").
//! - Character set: Personalausweisverordnung (PAuswV), Anlage (formerly
//!   Anhang) 3 "Formale Anforderungen an die Einträge in Ausweisen",
//!   Abschnitt 1, Vorbemerkung Nr. 9, in the Bundesministerium des Innern
//!   texts submitted to the Bundesrat (retrieved 2026-10-31 from the
//!   Bundestag document server):
//!   - BR-Drucksache 765/12 of 12.12.2012, Art. 2 Nr. 7 (new Anhang 3
//!     Abschnitt 1), <https://dserver.bundestag.de/brd/2012/0765-12.pdf>,
//!     and BR-Drucksache 219/15 of 13.05.2015, Art. 1 Nr. 6,
//!     <https://dserver.bundestag.de/brd/2015/0219-15.pdf>: "Die
//!     alphanummerische Seriennummer des Personalausweises wird
//!     ausschließlich aus den Buchstaben C, F, G, H, J, K, L, M, N, P, R,
//!     T, V, W, X, Y, Z und den Ziffern 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
//!     gebildet. Beim vorläufigen Personalausweis und beim
//!     Ersatz-Personalausweis besteht die Seriennummer aus einem
//!     Buchstaben und sieben Ziffern."
//!   - BR-Drucksache 395/21 of 10.05.2021,
//!     <https://dserver.bundestag.de/brd/2021/0395-21.pdf>, Art. 3 Nr. 23
//!     Buchstabe a: "In der Vorbemerkung wird in Nummer 9 Satz 1 nach dem
//!     Wort "Ziffern" die Angabe "0," gestrichen."; Art. 5 Abs. 3: in
//!     force on 1 November 2021; Begründung: "Bei der Eingabe der
//!     Seriennummer in elektronische Formulare kommt es bei der Ziffer 0
//!     zu Verwechslungen mit dem Großbuchstaben O. ... Daher soll die
//!     Ziffer 0 künftig in diesem Kontext nicht mehr verwendet werden."
//!   - The current Anlage 3 title is listed in Bundesgesetzblatt 2026 I
//!     Nr. 31, Art. 3 Nr. 1 (Inhaltsübersicht of the PAuswV),
//!     <https://www.recht.bund.de/bgbl/1/2026/31/regelungstext.pdf?__blob=publicationFile&v=1>
//!     (retrieved 2026-10-31); that amendment only renames "Anhang" to
//!     "Anlage" (Art. 3 Nr. 40). The enacted Bundesgesetzblatt texts of
//!     2013-2021 and the consolidated PAuswV were not reachable from the
//!     retrieving host (BR-Drucksache 219/15 cites the 2012 text as Art. 2
//!     of the Verordnung of 20 February 2013, BGBl. I S. 330).
//!
//! The ICAO check digit is a separate MRZ element and NOT the
//! ninth character of the serial number: the validator checks the format
//! only. Accepted: nine characters from the Nr. 9 set (the letters C F G
//! H J K L M N P R T V W X Y Z and the digits), or one uppercase letter +
//! seven digits (provisional and replacement identity card; Satz 2 does
//! not restrict that letter). The digit 0 stays accepted: it left the set
//! only for cards issued from 1 November 2021, and cards issued before
//! keep their serial number ("künftig").
//!
//! Cue policy: no checksum exists, so a cue is REQUIRED (score 0.9,
//! format + mandatory cue). The cues are German labels only: the format
//! covers many nine-character alphanumeric tokens, and a generic
//! English "identity card" cue would claim other countries' identity
//! card numbers of the same length (e.g. a Singapore NRIC next to its own
//! "identity card" cue) as German numbers when both packs are enabled.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): `ausweis` also covers "Personalausweis" and
/// "Ausweisnummer".
pub(super) const CUES: &[&str] = &["ausweis", "id-nummer"];

/// The letters of the nine-character serial number (PAuswV Anlage 3
/// Vorbemerkung Nr. 9 Satz 1); the digits complete the set.
const SERIAL_LETTERS: &[u8] = b"CFGHJKLMNPRTVWXYZ";

/// Returns `true` if `serial` has the format of a German identity card
/// serial number: nine characters from the PAuswV Anlage 3 Nr. 9 set (the
/// uppercase letters C F G H J K L M N P R T V W X Y Z and the digits
/// 0-9; four-character Behördenkennzahl + five random characters), or one
/// uppercase letter followed by seven digits (provisional and replacement
/// identity card). No check digit is part of the serial number.
///
/// # Examples
/// ```
/// use redactify::valid_de_id_card;
/// assert!(valid_de_id_card("LF2K7X9R2"));
/// assert!(valid_de_id_card("L01X00T4K")); // letters allowed in every position
/// assert!(valid_de_id_card("A1234567"));  // provisional identity card
/// assert!(!valid_de_id_card("BEANTRAGT")); // B, E, A outside the Nr. 9 set
/// assert!(!valid_de_id_card("LF2K7X9R"));  // 8 characters, not provisional
/// assert!(!valid_de_id_card("lf2k7x9r2")); // lowercase
/// ```
#[must_use]
pub fn valid_de_id_card(serial: &str) -> bool {
    let b = serial.as_bytes();
    match b.len() {
        9 => b
            .iter()
            .all(|c| c.is_ascii_digit() || SERIAL_LETTERS.contains(c)),
        8 => b[0].is_ascii_uppercase() && b[1..].iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeIdCard,
        // [CFGHJ-NPRTV-Z0-9] is the Nr. 9 set (J-N = J K L M N, V-Z = V W X Y Z)
        r"(?<![A-Z0-9])(?:[CFGHJ-NPRTV-Z0-9]{9}|[A-Z]\d{7})(?![A-Z0-9])",
        Some(valid_de_id_card),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_de_id_card;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn format_only() {
        // nine characters: every "check digit" variant is valid,
        // and the ninth character may be a letter
        for d in 0..10 {
            assert!(valid_de_id_card(&format!("LF2K7X9R{d}")));
        }
        for v in [
            "LF2K7X9RZ",
            "CF2K7X9R9",
            "123456789",
            "CFGHJKLMN",
            "PRTVWXYZ0",
        ] {
            assert!(valid_de_id_card(v), "{v}");
        }
        // PAuswV Anlage 3 Nr. 9: the other nine letters never occur
        for c in "ABDEIOQSU".chars() {
            let v = format!("LF2K7X9R{c}");
            assert!(!valid_de_id_card(&v), "{v}");
        }
        assert!(!valid_de_id_card("BEANTRAGT"));
        assert!(!valid_de_id_card("ABCDEFGHI"));
        // the digit 0 stays valid (cards issued before 1 November 2021)
        assert!(valid_de_id_card("L01X00T47"));
        // provisional identity card: one letter + seven digits
        assert!(valid_de_id_card("T1234567"));
        assert!(!valid_de_id_card("12345678"));
        assert!(!valid_de_id_card("TA234567"));
        // length, case and non-ASCII
        assert!(!valid_de_id_card("LF2K7X9R"));
        assert!(!valid_de_id_card("LF2K7X9R22"));
        assert!(!valid_de_id_card("LF2k7X9R2"));
        assert!(!valid_de_id_card("LF2K7X9RÄ"));
    }

    #[test]
    fn rule_requires_a_german_cue() {
        let ents = engine_detect("Personalausweis LF2K7X9RZ hinterlegt", &["de"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DeIdCard);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
        assert_eq!(engine_detect("ID-Nummer: T1234567", &["de"]).len(), 1);
        assert!(engine_detect("Ticket LF2K7X9RZ geprueft", &["de"]).is_empty());
        // the English generic cue does not unlock the shape
        assert!(engine_detect("identity card LF2K7X9RZ", &["de"]).is_empty());
        // a nine-letter word after the cue is not a serial number
        assert!(engine_detect("Personalausweis BEANTRAGT am Montag", &["de"]).is_empty());
    }
}
