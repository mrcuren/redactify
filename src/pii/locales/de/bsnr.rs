//! German practice site number (Betriebsstättennummer, BSNR): format
//! validator + rule. FORMAT ONLY - the source defines no check digit.
//!
//! Official source (retrieved 2026-10-30): Kassenärztliche
//! Bundesvereinigung, "Richtlinie der Kassenärztlichen Bundesvereinigung
//! nach § 75 Absatz 7 SGB V zur Vergabe der Arzt-, Betriebsstätten-,
//! Praxisnetz- sowie der Netzverbundnummern" (Stand 1. Januar 2024),
//! <https://www.kbv.de/documents/infothek/rechtsquellen/weitere-vertraege/praxen/arzt-und-betriebsstaettennummer/Arztnummern_Richtlinie.pdf>.
//!
//! - § 6 Abs. 1: "Die Betriebsstättennummer ist neunstellig. Die ersten
//!   beiden Ziffern stellen den KV-Landes- oder Bezirksstellenschlüssel
//!   gemäß Anlage 1 zu dieser Richtlinie dar. Die Ziffern drei bis neun
//!   werden von der KV vergeben."
//! - § 6 Abs. 3: for the special practice sites "enthalten die ersten
//!   beiden Ziffern den Wert "35"" (a.) or "den Wert "75"" (b.); the KV
//!   key then follows in digits 3-4.
//! - § 16 Abs. 1: network numbers (NVNR) start with "99" (not a BSNR).
//! - Anlage 1 (KV-Landes- und Bezirksstellenschlüssel): 01-03, 06-21, 24,
//!   25, 27, 28, 31, 37-73, 78-81, 83, 85-91, 93-96, 98.
//!
//! No official example number is published; the test vectors are
//! structural (Anlage 1 keys).
//!
//! Cue policy: no checksum exists, so a cue is REQUIRED (score 0.9,
//! format + mandatory cue). Registered after the checksummed LANR rule
//! (same 9-digit shape). A leading cue counts when its END lies within the
//! 18-character cue window before the value (`pii::context`), so the
//! 21-character "Betriebsstättennummer" is listed in full; the tails
//! `stättennummer` / `stätten-nr` stay as the catch-all for the other
//! "...stättennummer" / "...stätten-Nr." spellings.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, two_digits, ContextPolicy, Rule};

/// Cue words (lowercase): the full label "Betriebsstättennummer" first
/// (the reported cue is the first listed one that is found), then the
/// tails `stättennummer` / `stätten-nr` of the "...stättennummer" /
/// "...stätten-Nr." spellings.
pub(super) const CUES: &[&str] = &[
    "betriebsstättennummer",
    "bsnr",
    "betriebsstätte",
    "stättennummer",
    "stätten-nr",
];

/// KV-Landes- or Bezirksstellenschlüssel of Anlage 1.
const fn kv_key(k: u32) -> bool {
    matches!(
        k,
        1..=3 | 6..=21 | 24 | 25 | 27 | 28 | 31 | 37..=73 | 78..=81 | 83 | 85..=91 | 93..=96 | 98
    )
}

/// Returns `true` if `bsnr` has the Betriebsstättennummer format: nine
/// ASCII digits whose first two digits are an Anlage 1 KV key, or `35` /
/// `75` (§ 6 Abs. 3) followed by an Anlage 1 KV key in digits 3-4. No
/// check digit exists.
///
/// # Examples
/// ```
/// use redactify::valid_de_bsnr;
/// assert!(valid_de_bsnr("021234567")); // KV key 02
/// assert!(valid_de_bsnr("351712345")); // special site, KV key 17
/// assert!(!valid_de_bsnr("041234567")); // 04 is not an Anlage 1 key
/// assert!(!valid_de_bsnr("991234567")); // 99 = network number (NVNR)
/// ```
#[must_use]
pub fn valid_de_bsnr(bsnr: &str) -> bool {
    let b = bsnr.as_bytes();
    if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    match two_digits(&b[..2]) {
        35 | 75 => kv_key(two_digits(&b[2..4])),
        k => kv_key(k),
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DeBsnr,
        r"(?<!\d)\d{9}(?!\d)",
        Some(valid_de_bsnr),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{kv_key, valid_de_bsnr, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn anlage_1_keys() {
        let keys: Vec<u32> = (0..100).filter(|&k| kv_key(k)).collect();
        // 3 + 16 + 2 + 2 + 1 + 37 + 4 + 1 + 7 + 4 + 1
        assert_eq!(keys.len(), 78);
        for k in [
            0, 4, 5, 22, 23, 26, 29, 30, 32, 35, 36, 74, 75, 77, 82, 84, 92, 97, 99,
        ] {
            assert!(!kv_key(k), "{k}");
        }
    }

    #[test]
    fn structure() {
        assert!(valid_de_bsnr("021234567"));
        assert!(valid_de_bsnr("981234567"));
        assert!(valid_de_bsnr("351712345"));
        assert!(valid_de_bsnr("759812345"));
        assert!(!valid_de_bsnr("041234567"));
        assert!(!valid_de_bsnr("991234567"));
        assert!(!valid_de_bsnr("350412345")); // 35 + 04: no KV key
        assert!(!valid_de_bsnr("02123456"));
        assert!(!valid_de_bsnr("0212345678"));
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("BSNR 021234567 Praxis", &["de"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DeBsnr);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
        assert!(engine_detect("Praxis 021234567 offen", &["de"]).is_empty());
        for cue in CUES {
            let text = format!("{cue}: 351712345");
            assert_eq!(engine_detect(&text, &["de"]).len(), 1, "{text}");
        }
        // the full compound label is a cue of its own
        assert_eq!(
            engine_detect("Betriebsstättennummer: 021234567", &["de"]).len(),
            1
        );
    }
}
