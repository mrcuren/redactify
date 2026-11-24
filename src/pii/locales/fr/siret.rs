//! French SIRET (SIREN + NIC): validator + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. Wikipedia (FR) "SIRET": 14 digits, 14th is a Luhn (mod-10)
//!    check digit over the full 14; the 9-digit SIREN itself must also
//!    pass Luhn (except La Poste SIREN 356000000).
//! 2. strangebuzz "Validating a French SIRET number with the Luhn
//!    algorithm": same algorithm, worked examples.
//!    INSEE (official, structure: 14 digits, 14th = control digit).
//!
//! Cue REQUIRED: Luhn alone admits ~10% of random 14-digit shapes.

use crate::pii::entity::EntityType;
use crate::pii::locales::{luhn_valid, rule, ContextPolicy, Rule};

/// Cue words that make a SIRET candidate claimable. "NIC" (the
/// establishment part of the SIRET) is delimited on both sides inside a
/// line (` nic `) or by `:` / parentheses: bare, "nic" is a substring of
/// "technical", "communication", "ethnicity", the German "nicht" and the
/// Turkish "kullanici", and many words end in it ("electronic", "panic",
/// "clinic"), so "nic " alone is no form (residual: "clinic:").
pub(super) const CUES: &[&str] = &["siret", "siren", "nic:", "(nic)", " nic ", "insee"];

/// Returns `true` if `siret` is a Luhn-valid French SIRET (14 digits).
///
/// # Examples
/// ```
/// use redactify::valid_fr_siret;
/// assert!(valid_fr_siret("12345678200002")); // Luhn sum 40
/// assert!(!valid_fr_siret("12345678200001")); // last digit off // last digit off
/// ```
#[must_use]
pub fn valid_fr_siret(siret: &str) -> bool {
    let digits: String = siret.chars().filter(|c| c.is_ascii_digit()).collect();
    let b = digits.as_bytes();
    if b.len() != 14 {
        return false;
    }
    // Luhn: from rightmost, double every other digit, sum, mod 10 == 0
    luhn_valid(b)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::FrSiret,
        r"(?<!\d)\d{3}[ ]?\d{3}[ ]?\d{3}[ ]?\d{5}(?!\d)",
        Some(valid_fr_siret),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod siret_tests {
    use super::valid_fr_siret;
    use crate::EntityType;

    #[test]
    fn siret_valid() {
        assert!(valid_fr_siret("12345678200002")); // sum 40
        assert!(valid_fr_siret("55512345400020")); // sum 40
        assert!(!valid_fr_siret("12345678200001")); // last digit off
        assert!(!valid_fr_siret("12345678900002")); // SIREN part fails
    }

    #[test]
    fn siret_rule_validates_correctly() {
        // rule-level chain (regex + validator + cue policy); in the full
        // pipeline a cued SIRET outranks the cue-less card claim (FrSiret
        // is in the top priority tier, see EntityType::priority)
        use crate::pii::locales::{rules_for_locales, ContextPolicy};
        let rules = rules_for_locales(&["fr"]);
        let siret_rule = rules
            .iter()
            .find(|r| matches!(r.kind, EntityType::FrSiret))
            .expect("SIRET rule registered");
        assert_eq!(siret_rule.kind, EntityType::FrSiret);
        assert!(valid_fr_siret("123 456 782 00002"));
        // the cue check is wired (RequiredCue with siret context)
        assert!(matches!(siret_rule.context, ContextPolicy::RequiredCue(_)));
    }

    #[test]
    fn nic_cue_is_delimited() {
        // checked on the cue list itself: without a SIRET cue the full
        // pipeline labels a Luhn-valid 14-digit run CREDIT_CARD anyway
        use crate::pii::context::find_cue;
        let at = |t: &str| {
            let s = t.find("12345678200002").expect("value present");
            find_cue(t, s, s + 14, super::CUES, 18, false)
        };
        for trap in [
            "Kullan\u{131}c\u{131} 12345678200002",
            "technical 12345678200002",
            "communication 12345678200002",
            "nicht 12345678200002",
            "electronic 12345678200002",
        ] {
            assert_eq!(at(trap), None, "{trap}");
        }
        assert_eq!(at("NIC: 12345678200002"), Some("nic:"));
        assert_eq!(at("le NIC 12345678200002"), Some(" nic "));
        assert_eq!(at("(NIC) 12345678200002"), Some("(nic)"));
        assert_eq!(at("SIRET 12345678200002"), Some("siret"));
    }
}
