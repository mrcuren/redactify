//! Locale-independent rules: e-mail and credit card (Luhn).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `number` passes the Luhn checksum.
///
/// Non-digit characters are ignored (space/dash separators); at least **13**
/// digits are required. Every second digit, starting from the second one on the
/// right, is doubled; values above 9 have 9 subtracted; the sum must be a
/// multiple of 10.
///
/// # Examples
/// ```
/// use redactify::valid_luhn;
/// assert!(valid_luhn("4111111111111111"));
/// assert!(!valid_luhn("4111111111111112"));
/// ```
#[must_use]
pub fn valid_luhn(number: &str) -> bool {
    let digits: Vec<u32> = number
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| u32::from(b - b'0'))
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let parity = digits.len() % 2;
    let checksum: u32 = digits
        .iter()
        .enumerate()
        .map(|(i, &d)| {
            let mut x = d;
            if i % 2 == parity {
                x *= 2;
                if x > 9 {
                    x -= 9;
                }
            }
            x
        })
        .sum();
    checksum % 10 == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn email_rule() -> Rule {
    rule!(
        EntityType::Email,
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
        None,
        ContextPolicy::None,
        0.85
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn card_rule() -> Rule {
    rule!(
        EntityType::CreditCard,
        r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
        Some(valid_luhn),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_luhn;

    #[test]
    fn golden_vectors() {
        assert!(valid_luhn("4111111111111111"));
        assert!(valid_luhn("4111 1111 1111 1111"));
        assert!(valid_luhn("4111-1111-1111-1111"));
        assert!(!valid_luhn("4111111111111112"));
        assert!(!valid_luhn("411111111111"));
        assert!(!valid_luhn(""));
        assert!(!valid_luhn("4111 1111 1111 111x"));
    }
}
