//! German PLZ (Postleitzahl): detection rule (structural,
//! no checksum exists). Evidence (two independent
//! sources, retrieved 2026-10-08):
//! An independent public rule set: `\b(?!01000\b|99999\b)(0[1-9]\d{3}|[1-9]\d{4})\b`
//! at very low base confidence with context "plz", "postleitzahl"
//! (plus broad address words deliberately not reused here).
//! Wikipedia "Postleitzahl (Germany)" / Deutsche Post postcode
//! directory: five digits in the assigned range 01001-99998; the exact
//! bookends 01000 and 99999 were never assigned.
//!
//! FP policy (NINO precedent): a bare 5-digit run is a ubiquitous
//! order/serial shape, so a cue is REQUIRED and the score stays at
//! 0.9. Only the label cues are used; the broad rule-set context words
//! ("ort", "adresse", "wohnort") are common German words that would
//! unlock the shape from ordinary prose (documented deviation).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a PLZ candidate claimable. The bare "plz" from
/// the public rule-set context list is deliberately omitted: as a substring it
/// is also the English internet slang "please", which unlocked the
/// shape from ordinary prose (FPR-canary catch, documented deviation);
/// the colon label form covers the realistic German usages.
pub(super) const CUES: &[&str] = &["plz:", "postleitzahl"];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DePlz,
        r"(?<!\d)(?!01000\b|99999\b)(?:0[1-9]\d{3}|[1-9]\d{4})(?!\d)",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    fn kinds(text: &str) -> Vec<EntityType> {
        engine_detect(text, &["de"])
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn assigned_plz_with_cue_detected() {
        // real postcodes (Deutsche Post directory): Dresden, Berlin,
        // Munich, Frankfurt an der Oder (smallest), Hof (largest area
        // bookend below 99999)
        for plz in ["01067", "10115", "80331", "15230", "95028"] {
            assert_eq!(
                kinds(&format!("PLZ: {plz} angeben")),
                vec![EntityType::DePlz],
                "{plz}"
            );
        }
        assert_eq!(kinds("Postleitzahl 10115 berlin"), vec![EntityType::DePlz]);
    }

    #[test]
    fn unassigned_bookends_and_no_cue_stay_silent() {
        // the exact bookends were never assigned
        assert!(kinds("PLZ: 01000 teste").is_empty());
        assert!(kinds("PLZ: 99999 teste").is_empty());
        // no cue: a bare 5-digit run is never claimed
        assert!(kinds("bestellung 10115 versendet").is_empty());
        // the omitted slang cue must NOT unlock the shape
        assert!(kinds("plz send 40732 refs").is_empty());
        // 4 or 6 digits are not PLZ shapes
        assert!(kinds("PLZ: 1015 testen").is_empty());
        assert!(kinds("PLZ: 101155 testen").is_empty());
        // the omitted broad cues must NOT unlock the shape
        assert!(kinds("wohnort 10115 schoen").is_empty());
        assert!(kinds("adresse 80331 da").is_empty());
    }
}
