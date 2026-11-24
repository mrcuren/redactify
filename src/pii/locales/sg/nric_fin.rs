//! Singapore NRIC/FIN: validator + rule.
//! Evidence (two sources, retrieved 2026-10-08):
//! An independent public rule set: patterns `\b[A-Z]\d{7}[A-Z]\b`
//! (weak) and `\b[STFGM]\d{7}[A-Z]\b` (medium, score 0.5), context
//! "fin", "nric"; NO checksum validation.
//! Wikipedia "National Registration Identity Card": the format is
//! prefix letter + 7 digits + a checksum letter; the prefixes `S`/`T`
//! (NRIC) and `F`/`G`/`M` (FIN) are documented, and the checksum
//! algorithm "is not publicly available" (sold by the Ministry of Home
//! Affairs to organisations with a legitimate need); the reverse-
//! engineered variants circulating publicly do not reproduce the
//! article's own example numbers, so none of them is trusted here.
//!
//! Therefore this rule is STRUCTURAL ONLY (no checksum exists for us):
//! a cue is REQUIRED and the score stays at 0.9 (NINO/passport
//! precedent). Upper-case canonical form only.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make an NRIC/FIN candidate claimable. The bare "fin"
/// from the public rule set's context list is deliberately omitted: as a
/// substring it also matches finance/find/final, which would let
/// ordinary prose unlock the shape (documented deviation). "nric" is
/// delimited (`nric:`, `nric/` ...): bare, it is a substring of "enrich",
/// "enriched" and "enrichment".
pub(super) const CUES: &[&str] = &[
    "nric:",
    "nric ",
    "nric#",
    "nric-",
    "nric/",
    "(nric)",
    "fin number",
    "identity card",
];

/// Returns `true` if `id` is a structurally valid Singapore NRIC/FIN:
/// `S`/`T`/`F`/`G`/`M` + 7 digits + an upper-case letter (no checksum
/// is applied - the algorithm is not publicly available).
///
/// # Examples
/// ```
/// use redactify::valid_sg_nric_fin;
/// assert!(valid_sg_nric_fin("S2740116C")); // public rule-set docstring example
/// assert!(!valid_sg_nric_fin("B2740116C")); // B is not a prefix letter
/// assert!(!valid_sg_nric_fin("s2740116c")); // lower case
/// assert!(!valid_sg_nric_fin("S2740116"));  // missing check letter
/// ```
#[must_use]
pub fn valid_sg_nric_fin(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 9 {
        return false;
    }
    if !matches!(b[0], b'S' | b'T' | b'F' | b'G' | b'M') {
        return false;
    }
    if !b[1..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    b[8].is_ascii_uppercase()
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::SgNricFin,
        r"(?<![A-Z0-9])[STFGM]\d{7}[A-Z](?![A-Z0-9])",
        Some(valid_sg_nric_fin),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_sg_nric_fin;

    #[test]
    fn structural_rules() {
        assert!(valid_sg_nric_fin("S2740116C")); // structural: no checksum
        assert!(valid_sg_nric_fin("T0123456Z"));
        assert!(valid_sg_nric_fin("F5432101B"));
        assert!(valid_sg_nric_fin("G1234567K"));
        assert!(valid_sg_nric_fin("M7654321D"));
        assert!(!valid_sg_nric_fin("B2740116C"));
        assert!(!valid_sg_nric_fin("s2740116c"));
        assert!(!valid_sg_nric_fin("S2740116"));
        assert!(!valid_sg_nric_fin("S2740116c1"));
    }
}
