//! French NIR (numéro de sécurité sociale / INSEE): validator + rule.
//! Evidence: INSEE/Wikipedia "INSEE code" +
//! fr.wikipedia "Numéro de sécurité sociale en France" (retrieved 2026-10-06):
//! 13 digits + 2-digit key (01-97), key = 97 − (NIR13 mod 97); Corsica
//! departments 2A/2B are replaced by 19/18 before the modulo.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `nir` is a valid French NIR (15 characters with the
/// department written as `2A`/`2B` for Corsica, 15 digits otherwise; single
/// internal spaces tolerated and stripped).
///
/// Structure: sex(1, must be 1/2) year(2) month(2, 01-12) department(2, or
/// 2A/2B) commune(3) order(3) key(2 = 97 − rest mod 97, with 2A→19, 2B→18).
///
/// Limits: month must be a real month 01-12
/// (legacy "unknown month" codes 20+ are rejected); department digits are not
/// checked against the official department table (only the checksum decides).
///
/// # Examples
/// ```
/// use redactify::valid_nir;
/// // Wikipedia Corsica transformation example, key computed (18):
/// assert!(valid_nir("263072A10406418"));
/// // one key digit changed -> invalid
/// assert!(!valid_nir("263072A10406419"));
/// ```
#[must_use]
pub fn valid_nir(nir: &str) -> bool {
    let s: String = nir.chars().filter(|c| !c.is_whitespace()).collect();
    let b = s.as_bytes();
    // both forms are 15 characters: all digits, or with the Corsica
    // department `2A`/`2B` at characters 6..8 (the department is always 2
    // characters wide, letters included)
    if b.len() != 15 {
        return false;
    }
    let numeric: String = if b[5] == b'2' && (b[6] == b'A' || b[6] == b'B') {
        if !b[..5].iter().all(u8::is_ascii_digit) || !b[7..].iter().all(u8::is_ascii_digit) {
            return false;
        }
        // official rule: 2A -> 19, 2B -> 18 before the modulo
        let repl = if b[6] == b'A' { "19" } else { "18" };
        format!("{}{}{}", &s[..5], repl, &s[7..])
    } else {
        if !b.iter().all(u8::is_ascii_digit) {
            return false;
        }
        s.clone()
    };
    // structural fields (sex enforced by the pattern; month validated here)
    let month: u32 = match numeric[3..5].parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !(1..=12).contains(&month) {
        return false;
    }
    let rest: u32 = {
        let n13: u128 = match numeric[..13].parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        u32::try_from(n13 % 97).unwrap_or(97)
    };
    let key: u32 = match numeric[13..15].parse() {
        Ok(k) => k,
        Err(_) => return false,
    };
    key == 97 - rest
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Nir,
        r"(?<![\w])[12] ?\d{2} ?\d{2} ?(?:2[AB]|\d{2}) ?\d{3} ?\d{3} ?\d{2}(?!\d)",
        Some(valid_nir),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_nir;

    #[test]
    fn key_math() {
        // generated: 13 digits, key computed (see tools corpus note)
        let base = "1510247260123";
        let n: u128 = base.parse().unwrap();
        let key = 97 - (n % 97);
        let full = format!("{base}{key:02}");
        assert!(valid_nir(&full), "{full}");
        // spaced form
        assert!(valid_nir("2 63 07 2A 104 064 18"));
        // checksum failure
        assert!(!valid_nir("151024726012400"));
    }

    #[test]
    fn month_must_be_real() {
        let base = "1513007260123"; // month 13
        let n: u128 = base.parse().unwrap();
        let key = 97 - (n % 97);
        assert!(!valid_nir(&format!("{base}{key:02}")));
    }
}
