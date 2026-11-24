//! German Steuer-IdNr (steuerliche Identifikationsnummer): validator + rule.
//!
//! Official source (retrieved 2026-10-30, re-read 2026-10-31):
//! Bayerisches Landesamt für Steuern (ELSTER), "Prüfung der Steuer- und
//! Steueridentifikationsnummer sowie der Ordnungskriterien bei der
//! Grundsteuer" (Stand: 02. September 2026),
//! <https://download.elster.de/download/schnittstellen/Pruefung_der_Steuer_und_Steueridentifikatsnummer.pdf>,
//! Kap. 2.2 "Aufbau der Steueridentifikationsnummer (IdNr)":
//!
//! - "Die Steueridentifikationsnummer ist eine elfstellige Ziffernfolge,
//!   die elfte Stelle ist eine Prüfziffer."
//! - "Keine führenden Nullen erlaubt, außer es ist eine
//!   Testidentifikationsnummer"
//! - "In den ersten 10 Stellen der Identifikationsnummer muss genau eine
//!   Ziffer doppelt oder dreifach vorkommen."
//! - "Existieren drei gleiche Ziffern an den Positionen 1 bis 10, dürfen
//!   diese gleichen Ziffern niemals an direkt aufeinander folgenden Stellen
//!   stehen."
//! - The check-digit routine `calcPruefzifferSteuerID` (ISO/IEC 7064
//!   MOD 11,10 in iterative form), transcribed below.
//! - Tabelle 2-1 examples: `86095742719`, `47036892816` (a doubled digit),
//!   `65929970489`, `57549285017`, `25768131411` (a tripled digit), and
//!   the test number `02476291358`.
//!
//! Reading of the tripled-digit sentence: the official example
//! `65929970489` has its tripled 9 at positions 3, 5 and 6, so a pairwise
//! reading ("no two of them adjacent") would reject an official example.
//! The validator applies the reading consistent with every Tabelle 2-1
//! example: the three equal digits must not occupy three consecutive
//! positions. Test numbers with a leading zero are rejected (they never
//! appear in real data).
//!
//! A cue is REQUIRED: a single check digit admits about 10% of random
//! 11-digit shapes (VKN/BSN precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue phrases (lowercase matching) that make a Steuer-IdNr claimable.
/// `idnr` is the common German abbreviation. A leading cue counts when its
/// END lies within the 18-character cue window before the number
/// (`pii::context`), so the official 27-character label
/// "Steueridentifikationsnummer" (ELSTER) and "Identifikationsnummer" are
/// matched whole; no in-window tail such as `tifikationsnummer` is needed.
pub(super) const CUES: &[&str] = &[
    "steueridentifikationsnummer",
    "steuer-id",
    "identifikationsnummer",
    "idnr",
];

/// Kap. 2.2 digit-structure rule over the first ten digits: exactly one
/// digit value occurs more than once, it occurs two or three times, and a
/// tripled value does not fill three consecutive positions.
fn structure_ok(first_ten: &[u8]) -> bool {
    let mut count = [0u8; 10];
    for &c in first_ten {
        count[usize::from(c - b'0')] += 1;
    }
    let mut repeated = count.iter().enumerate().filter(|&(_, &n)| n > 1);
    let (Some((digit, &n)), None) = (repeated.next(), repeated.next()) else {
        return false;
    };
    let digit = b'0' + u8::try_from(digit).unwrap_or(0);
    match n {
        2 => true,
        3 => !first_ten.windows(3).any(|w| w.iter().all(|&c| c == digit)),
        _ => false,
    }
}

/// Returns `true` if `id` is a valid German Steuer-IdNr: 11 digits, first
/// digit 1-9, the ELSTER Kap. 2.2 digit structure (exactly one digit
/// doubled or tripled in the first ten, a tripled digit never in three
/// consecutive positions), and the check digit (11th) of the ELSTER
/// routine over the first ten digits.
///
/// # Examples
/// ```
/// use redactify::valid_de_tax_id;
/// assert!(valid_de_tax_id("86095742719")); // ELSTER Tabelle 2-1
/// assert!(valid_de_tax_id("65929970489")); // tripled 9 (positions 3, 5, 6)
/// assert!(!valid_de_tax_id("86095742718")); // check digit changed
/// assert!(!valid_de_tax_id("97144838384")); // check digit fits, three repeated digits
/// assert!(!valid_de_tax_id("02476291358")); // test number (leading zero)
/// ```
#[must_use]
pub fn valid_de_tax_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 11 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if b[0] == b'0' || !structure_ok(&b[..10]) {
        return false;
    }
    // ELSTER calcPruefzifferSteuerID, verbatim structure
    let mut produkt: u32 = 10;
    for &c in &b[..10] {
        let d = u32::from(c - b'0');
        let mut summe = (d + produkt) % 10;
        if summe == 0 {
            summe = 10;
        }
        produkt = (summe * 2) % 11;
    }
    let mut pruefziffer = 11 - produkt;
    if pruefziffer == 10 {
        pruefziffer = 0;
    }
    pruefziffer == u32::from(b[10] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeTaxId,
        r"(?<!\d)[1-9]\d{10}(?!\d)",
        Some(valid_de_tax_id),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{structure_ok, valid_de_tax_id};

    #[test]
    fn official_examples() {
        // ELSTER Tabelle 2-1 ("ID laut Konzept des ITZ BUND")
        for v in [
            "86095742719",
            "47036892816",
            "65929970489",
            "57549285017",
            "25768131411",
        ] {
            assert!(valid_de_tax_id(v), "{v}");
        }
        // the Tabelle 2-1 test number: check digit and structure fit, but
        // the leading zero is reserved for test numbers
        assert!(structure_ok(b"0247629135"));
        assert!(!valid_de_tax_id("02476291358"));
        // single-digit substitutions of the check digit are caught
        assert!(!valid_de_tax_id("86095742718"));
        assert!(!valid_de_tax_id("8609574271"));
    }

    #[test]
    fn structure_rule() {
        // these generated vectors pass the check digit but have more
        // than one repeated digit value
        for v in ["97144838384", "78010311476", "35301272329", "63110672067"] {
            assert!(!structure_ok(&v.as_bytes()[..10]), "{v}");
            assert!(!valid_de_tax_id(v), "{v}");
        }
        assert!(structure_ok(b"1234567891")); // one doubled digit
        assert!(structure_ok(b"1123456781")); // tripled, two of them adjacent
        assert!(!structure_ok(b"1112345678")); // tripled in a row
        assert!(!structure_ok(b"1234567890")); // no repeated digit
        assert!(!structure_ok(b"1111234567")); // a digit four times
        assert!(!structure_ok(b"1122345678")); // two repeated digits
    }
}
