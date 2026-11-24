//! German health insurance number (Krankenversichertennummer), the
//! unchangeable part "Versicherten-ID": validator + rule.
//!
//! Official sources (retrieved 2026-10-30):
//! - Kassenärztliche Bundesvereinigung, "Datensatzbeschreibung KVDT",
//!   Version 6.06 of 8 July 2026 (document status "in Kraft"),
//!   <https://update.kbv.de/ita-update/Vorquartale/ita_update_2026_Q3/Abrechnung/KBV_ITA_VGEX_Datensatzbeschreibung_KVDT.pdf>,
//!   field 3119 "Versicherten_ID" and rule 054. Field 3119: "Die
//!   Prüfziffer wird mit einem Modulo-10-Verfahren ermittelt. Der
//!   Buchstabe wird dabei durch zwei Ziffern ersetzt, das A mit 0 und 1,
//!   das B mit 0 und 2, ..., und das Z mit 2 und 6. Die Ziffern werden von
//!   links nach rechts abwechselnd mit 1 und 2 multipliziert. Es erfolgt
//!   eine Quersummenbildung der einzelnen Produkte, mit anschließender
//!   Summenbildung der Quersummen. Die Prüfziffer ergibt sich aus dem Rest
//!   der ganzzahligen Division dieser Summe durch 10." Rule 054: format
//!   `annnnnnnnP` (one letter, eight digits, check digit), value not
//!   equal to the pseudo number `T555558879`. The field cites Anlage 1
//!   of the GKV-Spitzenverband guideline under § 290 SGB V, which was not
//!   reachable; the KBV specification is the binding billing-data
//!   specification that reproduces it.
//! - KBV "Prüfpaket KVDT Hybrid-DRG", Version 1.5 of 13 January 2025,
//!   <https://update.kbv.de/ita-update/Abrechnung/Hybrid-DRG/KBV_ITA_AHEX_Pruefpaket_KVDT_Hybrid-DRG.pdf>,
//!   sections 3.2.1.1 / 3.2.1.2 (fictitious official test data):
//!   "Versicherten_ID E543768738 ... Versicherten_ID G894698435".
//!
//! Cue policy: a single mod-10 check digit admits about 10% of random
//! letter + 9 digit shapes, so a cue is REQUIRED (score 1.0, checksum
//! verified; Steuer-IdNr precedent). Cues are the identifier's names. A
//! leading cue counts when its END lies within the 18-character cue window
//! before the value (`pii::context`), so the full compounds
//! "Krankenversichertennummer" and "Versichertennummer" are listed as
//! such; their common tail `sichertennummer` stays as the catch-all for
//! the other "...versichertennummer" spellings.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase). The full compounds come first (the matched cue
/// reported by `Detector::explain` is the first listed one that is
/// found); `sichertennummer` is their common tail; `egk-` covers the
/// "eGK-Nr." / "eGK-Nummer" labels (a bare `egk` would match inside
/// German words such as "wegkommen").
pub(super) const CUES: &[&str] = &[
    "krankenversichertennummer",
    "versichertennummer",
    "sichertennummer",
    "versicherten-id",
    "versicherten-nr",
    "kvnr",
    "gesundheitskarte",
    "egk-",
];

/// The KBV pseudo number that passes the check digit but is never issued
/// (KVDT rule 054).
const PSEUDO: &str = "T555558879";

/// Returns `true` if `id` is a valid Versicherten-ID: one uppercase letter
/// `A`-`Z`, eight digits and the KVDT field 3119 check digit (the letter
/// replaced by its two-digit alphabet position, the ten digits weighted
/// 1, 2, 1, 2, ... from the left, the digit sums of the products added,
/// the sum modulo 10). The KBV pseudo number `T555558879` is rejected.
///
/// # Examples
/// ```
/// use redactify::valid_de_kvnr;
/// assert!(valid_de_kvnr("E543768738")); // KBV test data
/// assert!(!valid_de_kvnr("E543768739")); // check digit off
/// assert!(!valid_de_kvnr("T555558879")); // KBV pseudo number
/// assert!(!valid_de_kvnr("e543768738")); // lowercase letter
/// ```
#[must_use]
pub fn valid_de_kvnr(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 10 || !b[0].is_ascii_uppercase() || !b[1..].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if id == PSEUDO {
        return false;
    }
    let pos = u32::from(b[0] - b'A') + 1;
    let digits = [pos / 10, pos % 10]
        .into_iter()
        .chain(b[1..9].iter().map(|&c| u32::from(c - b'0')));
    let sum: u32 = digits
        .enumerate()
        .map(|(i, d)| {
            let p = if i % 2 == 0 { d } else { d * 2 };
            p / 10 + p % 10
        })
        .sum();
    sum % 10 == u32::from(b[9] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeKvnr,
        r"(?<![A-Za-z0-9])[A-Z]\d{9}(?![A-Za-z0-9])",
        Some(valid_de_kvnr),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_de_kvnr, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn official_test_data_and_rejections() {
        for v in ["E543768738", "G894698435"] {
            assert!(valid_de_kvnr(v), "{v}");
        }
        // every other check digit is rejected
        for d in (0..10).filter(|&d| d != 8) {
            assert!(!valid_de_kvnr(&format!("E54376873{d}")));
        }
        assert!(!valid_de_kvnr("T555558879"));
        assert!(!valid_de_kvnr("E54376873"));
        assert!(!valid_de_kvnr("E5437687380"));
        assert!(!valid_de_kvnr("1543768738"));
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("Versichertennummer: E543768738", &["de"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DeKvnr);
        assert!(engine_detect("Ticket E543768738 erledigt", &["de"]).is_empty());
        for cue in CUES {
            let text = format!("{cue} G894698435");
            assert_eq!(engine_detect(&text, &["de"]).len(), 1, "{text}");
        }
    }
}
