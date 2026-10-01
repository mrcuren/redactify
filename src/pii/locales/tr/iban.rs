//! Turkish IBAN: validator + detection rule (pattern + mod-97 checksum).

/// Returns `true` if `iban` is a valid Turkish IBAN.
///
/// Rules: spaces are stripped and letters uppercased; the value must be `TR`
/// followed by exactly 24 digits; then the standard mod-97 check runs
/// (rearrangement: BBAN + country + check digits, characters interpreted
/// base-36, expecting `mod 97 == 1`).
///
/// # Examples
/// ```
/// use redactify::valid_iban_tr;
/// assert!(valid_iban_tr("TR33 0006 1005 1978 6457 8413 26"));
/// assert!(!valid_iban_tr("TR00 0000 0000 0000 0000 0000 00"));
/// assert!(!valid_iban_tr("TR33 0006 1005 1978 6457 8413 27")); // one digit changed
/// ```
#[must_use]
pub fn valid_iban_tr(iban: &str) -> bool {
    let s: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect();
    let b = s.as_bytes();
    if b.len() != 26 || b[0] != b'T' || b[1] != b'R' || !b[2..].iter().all(u8::is_ascii_digit) {
        return false;
    }
    // Rearrange: BBAN(24) + "TR" + check(2); streamed mod-97 left to right (no bigint needed).
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

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Iban,
        r"(?i)TR\d{2}(?:\s?\d{4}){5}\s?\d{2}",
        Some(valid_iban_tr),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_iban_tr;

    #[test]
    fn golden_vectors() {
        assert!(valid_iban_tr("TR33 0006 1005 1978 6457 8413 26"));
        assert!(valid_iban_tr("TR330006100519786457841326")); // spaceless
        assert!(valid_iban_tr("tr33 0006 1005 1978 6457 8413 26")); // lowercase
        assert!(!valid_iban_tr("TR00 0000 0000 0000 0000 0000 00"));
        assert!(!valid_iban_tr("TR33 0006 1005 1978 6457 8413 27"));
        assert!(!valid_iban_tr("TR33000610051978645784132")); // 25 digits
        assert!(!valid_iban_tr(""));
        assert!(!valid_iban_tr("DE89 3704 0044 0532 0130 00")); // not TR
    }
}
