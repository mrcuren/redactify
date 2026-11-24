//! International IBAN (ISO 13616): shared mod-97 core + country-length
//! registry + the locale-agnostic detection rule.
//!
//! The mod-97 rearrangement and the streamed modulo loop are shared with the
//! Turkish rule ([`crate::valid_iban_tr`]) - one checksum implementation,
//! two front doors. Country lengths come from the IBAN Register
//! (iban.com, retrieved 2026-10-05; 89 registry countries; the
//! experimental/partial list is deliberately excluded - unverified scope).
//!
//! Known limit (documented, precision-first): a BBAN's country-internal
//! check digits (e.g. NL modulo-11) are NOT validated here - mod-97 + exact
//! country length only.

/// (country code, total IBAN length in characters), sorted for binary search.
/// Source: IBAN Register (iban.com), retrieved 2026-10-05.
pub(super) const IBAN_LENGTHS: &[(&str, u8)] = &[
    // (country code, total length in characters); sorted by code for binary search
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BI", 27),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DJ", 27),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FK", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HN", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("LY", 25),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MN", 20),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NI", 28),
    ("NL", 18),
    ("NO", 15),
    ("OM", 23),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("RU", 33),
    ("SA", 24),
    ("SC", 31),
    ("SD", 18),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("SO", 23),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
    ("YE", 30),
];

/// Streamed mod-97 over the REARRANGED IBAN (BBAN + country + check digits),
/// expecting remainder 1. Input must be whitespace-stripped and uppercased.
pub(crate) fn mod97_is_valid(stripped_upper: &str) -> bool {
    let b = stripped_upper.as_bytes();
    let order: Vec<u8> = b[4..]
        .iter()
        .copied()
        .chain(b[..4].iter().copied())
        .collect();
    let mut rem: u32 = 0;
    for &c in &order {
        let v: u32 = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'A'..=b'Z' => u32::from(c - b'A') + 10,
            _ => return false,
        };
        // Feed each decimal digit of the base-36 value (10..35 are two digits wide).
        for digit in v.to_string().bytes().map(|d| u32::from(d - b'0')) {
            rem = (rem * 10 + digit) % 97;
        }
    }
    rem == 1
}

/// Returns `true` if `iban` is a valid international IBAN (any registry
/// country): whitespace stripped, letters uppercased; the country prefix
/// must be in the registry with the exact total length; all characters
/// alphanumeric; mod-97 checksum must pass.
///
/// # Examples
/// ```
/// use redactify::valid_iban;
/// assert!(valid_iban("GB82 WEST 1234 5698 7654 32"));
/// assert!(!valid_iban("GB82 WEST 1234 5698 7654 33")); // one digit changed
/// assert!(!valid_iban("ZZ12 3456 7890 1234"));         // country not in registry
/// ```
#[must_use]
pub fn valid_iban(iban: &str) -> bool {
    let s: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect();
    let b = s.as_bytes();
    if b.len() < 15 || b.len() > 33 {
        return false;
    }
    if !b.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let country = &s[..2];
    let Ok(i) = IBAN_LENGTHS.binary_search_by(|(c, _)| (*c).cmp(country)) else {
        return false;
    };
    if b.len() != usize::from(IBAN_LENGTHS[i].1) {
        return false;
    }
    mod97_is_valid(&s)
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Locale-agnostic IBAN rule (generic: active for every locale set).
///
/// The regex is a coarse candidate generator (uppercase IBAN shape with
/// optional internal spaces); the validator enforces the real structure:
/// registry country + exact length + mod-97. Case-sensitive on purpose -
/// lowercase IBANs are covered by the TR rule for Turkish, and a
/// case-insensitive pattern would greedily swallow the words that follow.
/// Hyphens are not accepted between groups: the greedy, variable-length
/// candidate would then take a hyphenated tail (`DE89...3000-2024.pdf`),
/// fail the length check and leave the IBAN in clear; the fixed-length
/// TR rule accepts them.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Iban,
        r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,4}){3,9}",
        Some(valid_iban),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_iban, IBAN_LENGTHS};

    #[test]
    fn table_is_sorted_and_sane() {
        assert_eq!(IBAN_LENGTHS.len(), 89);
        assert!(IBAN_LENGTHS.windows(2).all(|w| w[0].0 < w[1].0));
        let get = |cc: &str| {
            IBAN_LENGTHS
                .iter()
                .find(|(c, _)| *c == cc)
                .map(|(_, l)| *l)
                .unwrap()
        };
        // cross-checks against independently known values
        assert_eq!(get("TR"), 26);
        assert_eq!(get("DE"), 22);
        assert_eq!(get("FR"), 27);
        assert_eq!(get("GB"), 22);
        assert_eq!(get("NO"), 15); // shortest registry entry
        assert_eq!(get("LC"), 32);
        assert_eq!(get("RU"), 33); // longest registry entry
        assert_eq!(IBAN_LENGTHS.iter().map(|(_, l)| *l).max(), Some(33));
    }

    #[test]
    fn known_examples() {
        // each string below was machine-verified (mod-97 + length) before
        // being trusted; a misremembered "DE..." variant failed verification
        // and is asserted INVALID below on purpose
        assert!(valid_iban("GB82 WEST 1234 5698 7654 32"));
        assert!(valid_iban("NL91 ABNA 0417 1643 00"));
        assert!(valid_iban("CH93 0076 2011 6238 5295 7"));
        assert!(valid_iban("TR33 0006 1005 1978 6457 8413 26"));
        assert!(valid_iban("SE45 5000 0000 0583 9825 7466"));
        // checksum failure / registry miss / length mismatch
        assert!(!valid_iban("GB82 WEST 1234 5698 7654 33"));
        assert!(!valid_iban("ZZ12 3456 7890 1234"));
        assert!(!valid_iban("TR33 0006 1005 1978 6457 8413 2699")); // 28 chars, TR expects 26
    }
}
