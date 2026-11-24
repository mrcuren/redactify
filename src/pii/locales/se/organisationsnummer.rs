//! Swedish organisationsnummer (identity number of legal persons): format
//! validator + rule. FORMAT ONLY - the sources name a check digit but do
//! not state its algorithm, so it is not verified.
//!
//! Official sources (retrieved 2026-10-31):
//! - Lag (1974:174) om identitetsbeteckning för juridiska personer m.fl.,
//!   <https://www.riksdagen.se/sv/dokument-och-lagar/dokument/svensk-forfattningssamling/lag-1974174-om-identitetsbeteckning-for_sfs-1974-174/>,
//!   4 §: "Organisationsnummer består av tio siffror av vilka den sista är
//!   kontrollsiffra."
//! - Skatteverket, "Organisationsnummer", SKV 709 utgåva 8, served by the
//!   Swedish government e-identification framework's mirror of
//!   Skatteverket publications,
//!   <https://docs.swedenconnect.se/technical-framework/mirror/skv/skv709-8.pdf>,
//!   "Konstruktion": "Organisationsnummer består i likhet med personnummer
//!   av tio siffror. Den tredje siffran är alltid lägst en tvåa för att
//!   undvika förväxling med personnummer. Den sista siffran är en s.k.
//!   kontrollsiffra." (layout `G00000-000K`, G = Gruppnummer, K =
//!   Kontrollsiffra).
//!
//! Accepted forms: ten digits, optionally with a hyphen after the sixth
//! (the SKV 709 layout); the third digit is at least 2. The third-digit
//! rule makes the shape disjoint from a valid personnummer (month 20 or
//! more).
//!
//! Cue policy: the check digit is not verified, so a cue is REQUIRED
//! (score 0.9, format + mandatory cue). The 19-character
//! "organisationsnummer" cannot fit the 18-character cue window with a
//! separator, so its in-window tail is listed.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): `nisationsnummer` is the in-window tail of
/// "organisationsnummer"; the abbreviations are the common labels.
pub(super) const CUES: &[&str] = &["nisationsnummer", "org.nr", "orgnr", "org nr"];

/// Returns `true` if `number` has the organisationsnummer format: ten
/// ASCII digits (an optional hyphen after the sixth) whose third digit is
/// at least 2. The kontrollsiffra is not verified (no official algorithm).
///
/// # Examples
/// ```
/// use redactify::valid_se_organisationsnummer;
/// assert!(valid_se_organisationsnummer("556000-0000"));
/// assert!(valid_se_organisationsnummer("5560000000"));
/// assert!(!valid_se_organisationsnummer("551000-0000")); // third digit 1
/// assert!(!valid_se_organisationsnummer("556000000"));   // nine digits
/// ```
#[must_use]
pub fn valid_se_organisationsnummer(number: &str) -> bool {
    let b = number.as_bytes();
    let mut d = [0u8; 10];
    match b.len() {
        10 => d.copy_from_slice(b),
        11 if b[6] == b'-' => {
            d[..6].copy_from_slice(&b[..6]);
            d[6..].copy_from_slice(&b[7..]);
        }
        _ => return false,
    }
    d.iter().all(u8::is_ascii_digit) && d[2] >= b'2'
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::SeOrganisationsnummer,
        r"(?<![\d+\-])\d{6}-?\d{4}(?![\d\-])",
        Some(valid_se_organisationsnummer),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_se_organisationsnummer, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure() {
        assert!(valid_se_organisationsnummer("212000-0142"));
        assert!(valid_se_organisationsnummer("8020000000"));
        assert!(!valid_se_organisationsnummer("5510000000"));
        assert!(!valid_se_organisationsnummer("556000+0000"));
        assert!(!valid_se_organisationsnummer("55600-00000"));
        assert!(!valid_se_organisationsnummer("55600000000"));
        assert!(!valid_se_organisationsnummer("556000-000A"));
    }

    #[test]
    fn rule_requires_a_cue() {
        let ents = engine_detect("Organisationsnummer: 556000-0000", &["se"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::SeOrganisationsnummer);
        assert!(engine_detect("order 556000-0000 skickad", &["se"]).is_empty());
        for cue in CUES {
            let text = format!("{cue} 5560000000");
            assert_eq!(engine_detect(&text, &["se"]).len(), 1, "{text}");
        }
    }
}
