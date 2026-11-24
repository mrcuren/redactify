//! Polish NIP (Numerator Identyfikacji Podatkowej): validator + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. Wikipedia (PL) "NIP": 10 digits, weights (6,5,7,2,3,4,5,6,7)
//!    on digits 1-9, sum mod 11 = check digit; remainder 10 never
//!    issued.
//! 2. org-id.guide PL-NIP: same format; example 123-121-66-92 (check
//!    digit 2).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a NIP candidate claimable. "nip" and "vat" are
/// delimited (`nip:`, `vat ` ...): bare, "nip" is a substring of
/// "manipulate" and "snippet", "vat" of "private", "motivation",
/// "innovative" and "conservation". "tax" stays bare: delimiting it would
/// drop "taxes" and "taxpayer" (residual: "syntax", "taxi").
pub(super) const CUES: &[&str] = &[
    "nip:", "nip ", "nip#", "nip-", "nip/", "(nip)", "tax", "vat:", "vat ", "vat#", "vat-", "vat/",
    "(vat)", "podatk",
];

/// Returns `true` if `nip` is a checksum-valid Polish NIP (10 digits,
/// weighted mod-11).
///
/// # Examples
/// ```
/// use redactify::valid_pl_nip;
/// assert!(valid_pl_nip("1231216692")); // org-id.guide example
/// assert!(!valid_pl_nip("1234567890")); // wrong check digit
/// assert!(!valid_pl_nip("5272660010")); // remainder 10, never issued
/// ```
#[must_use]
pub fn valid_pl_nip(nip: &str) -> bool {
    let digits: String = nip.chars().filter(|c| c.is_ascii_digit()).collect();
    let b = digits.as_bytes();
    if b.len() != 10 {
        return false;
    }
    const WEIGHTS: [u32; 9] = [6, 5, 7, 2, 3, 4, 5, 6, 7];
    let sum: u32 = b
        .iter()
        .take(9)
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    let r = sum % 11;
    r != 10 && r == u32::from(b[9] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::PlNip,
        r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}(?!\d)",
        Some(valid_pl_nip),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod nip_tests {
    use super::valid_pl_nip;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn nip_valid() {
        assert!(valid_pl_nip("1231216692")); // org-id.guide
        assert!(valid_pl_nip("1234567802")); // sum=167, mod 11 = 2
        assert!(!valid_pl_nip("1234567890")); // wrong check digit
        assert!(!valid_pl_nip("5272660010")); // remainder 10
    }

    #[test]
    fn nip_detected_with_cue() {
        let ents = engine_detect("NIP 123-121-66-92", &["pl"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::PlNip), "{ents:?}");
    }

    #[test]
    fn nip_without_cue_not_claimed() {
        let ents = engine_detect("ref 123-121-66-92", &["pl"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::PlNip),
            "{ents:?}"
        );
    }
}
