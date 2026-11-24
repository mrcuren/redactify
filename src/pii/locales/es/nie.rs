//! Spanish NIE (número de identidad de extranjero): validator + rule.
//! Evidence (two independent implementations,
//! retrieved 2026-10-08; both trace the rule to the Ministerio del
//! Interior "Cálculo del dígito de control del NIF-NIE" calculator):
//! An independent public implementation: 9 characters, first `X`/`Y`/`Z`;
//!   the prefix is replaced via `'XYZ'.index(prefix)` (X=0, Y=1, Z=2)
//!   and the check letter is then computed exactly like a DNI
//!   (table[n mod 23]).
//! An independent public rule set: the same prefix mapping and the
//!   shared "TRWAGMYFPDXBNJZSQVHLCKE" table; context "número de
//!   identificación de extranjero", "nie"; optional dash before the
//!   control letter.
//!
//! A cue is REQUIRED: a single check letter admits ~4% of random shapes
//! (DNI precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::es::dni::LETTERS;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (i-normalized) that make an NIE candidate claimable. A
/// leading cue counts when its END lies within the 18-character cue window
/// before the value (`pii::context`), so the full phrase "número de
/// identidad de extranjero" (with and without the accent) is a cue; the
/// distinctive tail "extranjero" stays as the catch-all for the other
/// phrasings. The abbreviation is delimited (`nie:`, `nie ` ...): bare,
/// "nie" is a substring of "companies", "denied", "Daniel" and the German
/// "funktioniert", "Richtlinien" (residual: words that end in "nie" before
/// a space, e.g. "Stephanie", and the German and Polish word "nie").
pub(super) const CUES: &[&str] = &[
    "nie:",
    "nie ",
    "nie#",
    "nie-",
    "nie/",
    "(nie)",
    "número de identidad de extranjero",
    "numero de identidad de extranjero",
    "extranjero",
    "identidad de",
];

/// Returns `true` if `nie` is a valid Spanish NIE (`X`/`Y`/`Z` + 7
/// digits + control letter; optional dash before the letter; letter
/// matched case-insensitively).
///
/// # Examples
/// ```
/// use redactify::valid_nie;
/// assert!(valid_nie("X1234567L")); // 1234567 % 23 = 19 -> table[19] L
/// assert!(!valid_nie("X1234567K"));
/// assert!(!valid_nie("A1234567L")); // A is not an NIE prefix
/// assert!(!valid_nie("X123456L"));  // 6 digits
/// ```
#[must_use]
pub fn valid_nie(nie: &str) -> bool {
    let s: String = nie.trim().to_ascii_uppercase().replace('-', "");
    let b = s.as_bytes();
    if b.len() != 9 || !b[1..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let prefix: u64 = match b[0] {
        b'X' => 0,
        b'Y' => 1,
        b'Z' => 2,
        _ => return false,
    };
    let letter = b[8];
    if !letter.is_ascii_uppercase() {
        return false;
    }
    // the seven bytes are ASCII digits (checked above)
    let digits = b[1..8]
        .iter()
        .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0'));
    let n = prefix * 10_000_000 + digits;
    LETTERS[(n % 23) as usize] == letter
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Nie,
        r"(?i)(?<![A-Za-z0-9])[XYZ]\d{7}-?[A-Za-z](?![A-Za-z0-9])",
        Some(valid_nie),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_nie;

    #[test]
    fn prefix_mapping_math() {
        // generated + cross-verified: the number fed to the mod-23
        // division is prefix_value * 10^7 + 7-digit body, recomputed
        // here independently of the validator
        for (prefix, val) in [('X', 0u64), ('Y', 1), ('Z', 2)] {
            let body = "1234567";
            let n = val * 10_000_000 + body.parse::<u64>().unwrap();
            let expect = super::LETTERS[(n % 23) as usize];
            let nie = format!("{prefix}{body}{}", expect as char);
            assert!(valid_nie(&nie), "{nie}");
            // a wrong control letter is always rejected
            let wrong = if expect == b'K' { b'L' } else { b'K' };
            assert!(!valid_nie(&format!("{prefix}{body}{}", wrong as char)));
        }
        // body 0000000 isolates the prefix contribution: the mod-23
        // operand is exactly the prefix value times 10^7
        assert!(valid_nie("X0000000T")); // 0 % 23 = 0 -> table[0] T
        assert!(valid_nie("Y0000000Z")); // 10^7 % 23 = 14 -> table[14] Z
        assert!(valid_nie("Z0000000M")); // 2*10^7 % 23 = 5 -> table[5] M
                                         // case-insensitive letters, dash before the letter, bad shapes
        assert!(valid_nie("x1234567l"));
        assert!(valid_nie("X1234567-L"));
        assert!(!valid_nie("A1234567T"));
        assert!(!valid_nie("X123456T"));
        assert!(!valid_nie("X12345678T")); // 8 digits
    }
}
