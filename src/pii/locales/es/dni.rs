//! Spanish DNI: validator + rule. Evidence:
//! Wikipedia "Documento Nacional de Identidad (Spain)" (retrieved
//! 2026-10-06): 8 digits + control letter; letter = table[n mod 23] with
//! the table "TRWAGMYFPDXBNJZSQVHLCKE" (letters I, Ñ, O, U unused).
//!
//! A cue is REQUIRED: a single check letter admits ~4% of random
//! `digits+letter` shapes (VKN precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Control-letter table indexed by `number mod 23`. Shared with the NIE
/// rule (same table, same modulus).
pub(super) const LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Cue words (i-normalized) that make a DNI candidate claimable. `nif` is
/// included (NIF is the fiscal synonym of the same number). Both abbreviations are delimited
/// (`dni:`, `nif ` ...): bare, "dni" is a substring of "midnight" and the
/// Swedish "samordningsnummer", "nif" of "significant", "manifest",
/// "unify" and the French "planifier". `dnie` is the electronic DNI label.
pub(super) const CUES: &[&str] = &[
    "dni:",
    "dni ",
    "dni#",
    "dni-",
    "dni/",
    "(dni)",
    "dnie:",
    "dnie ",
    "nif:",
    "nif ",
    "nif#",
    "nif-",
    "nif/",
    "(nif)",
    "documento nacional",
    "carnet de identidad",
];

/// Returns `true` if `dni` is a valid Spanish DNI (8 digits + control
/// letter; the letter is matched case-insensitively).
///
/// # Examples
/// ```
/// use redactify::valid_dni;
/// assert!(valid_dni("12345678Z")); // 12345678 mod 23 -> table letter Z
/// assert!(!valid_dni("12345678X"));
/// assert!(!valid_dni("1234567Z")); // 7 digits
/// ```
#[must_use]
pub fn valid_dni(dni: &str) -> bool {
    let b = dni.trim().to_ascii_uppercase().as_bytes().to_vec();
    if b.len() != 9 || !b[..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let letter = b[8];
    if !letter.is_ascii_uppercase() {
        return false;
    }
    // the eight bytes are ASCII digits (checked above)
    let n = b[..8]
        .iter()
        .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0'));
    LETTERS[(n % 23) as usize] == letter
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Dni,
        r"(?<![\w])\d{8}[A-Za-z](?![A-Za-z0-9])",
        Some(valid_dni),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_dni;

    #[test]
    fn control_letter_math() {
        // letter computed, not remembered: 12345678 % 23 == 14 -> table[14]
        assert_eq!(super::LETTERS[(12345678 % 23) as usize], b'Z');
        assert!(valid_dni("12345678Z"));
        assert!(valid_dni("12345678z")); // case-insensitive letter
        assert!(!valid_dni("12345678X"));
        assert!(!valid_dni("123456789Z")); // 9 digits
        assert!(!valid_dni("1234567-Z")); // separator
    }
}
