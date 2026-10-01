//! Turkish national ID (TCKN): validator + detection rule (pattern + checksum).

/// Returns `true` if `n` is a valid TCKN.
///
/// Rules: exactly 11 ASCII digits, first digit is not `0`; the 10th digit is
/// `(sum of odd positions * 7 - sum of even positions) mod 10`, and the 11th
/// digit is the sum of the first 10 digits mod 10.
///
/// The weighted difference can be negative, so `rem_euclid` is used (a signed
/// `%` would produce a negative result and break validation).
///
/// # Examples
/// ```
/// use redactify::valid_tckn;
/// assert!(valid_tckn("12345678950"));
/// assert!(!valid_tckn("12345678901")); // check digits do not match
/// assert!(!valid_tckn("00000000000")); // leading zero not allowed
/// assert!(!valid_tckn("123"));          // wrong length
/// ```
#[must_use]
pub fn valid_tckn(n: &str) -> bool {
    let bytes = n.as_bytes();
    if bytes.len() != 11 || !bytes.iter().all(u8::is_ascii_digit) || bytes[0] == b'0' {
        return false;
    }
    let d: [u32; 11] = std::array::from_fn(|i| u32::from(bytes[i] - b'0'));
    // d[0:9:2] -> positions 0,2,4,6,8 ; d[1:8:2] -> positions 1,3,5,7
    let sum_odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let sum_even = d[1] + d[3] + d[5] + d[7];
    // The weighted difference can be NEGATIVE: i32 + rem_euclid gives a non-negative modulo.
    let d10 = ((sum_odd as i32) * 7 - sum_even as i32).rem_euclid(10) as u32;
    let d11 = (d[0..10].iter().sum::<u32>()) % 10;
    d[9] == d10 && d[10] == d11
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Tckn,
        r"(?<!\d)[1-9]\d{10}(?!\d)",
        Some(valid_tckn),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_tckn;

    #[test]
    fn golden_vectors() {
        assert!(valid_tckn("12345678950"));
        assert!(valid_tckn("10000000146"));
        assert!(!valid_tckn("12345678901"));
        assert!(!valid_tckn("00000000000"));
        assert!(!valid_tckn("02345678950")); // leading zero
        assert!(!valid_tckn("123"));
        assert!(!valid_tckn("123456789501")); // 12 digits
        assert!(!valid_tckn("1234567895a"));
        assert!(!valid_tckn(""));
    }

    #[test]
    fn negative_weighted_sum_is_handled() {
        // "19191919190": odd(d0,d2,...,d8)=1+1+1+1+1=5, even(d1,d3,d5,d7)=9*4=36
        // d10 = (5*7 - 36) = -1 -> negative; rem_euclid(10) = 9, a signed % would give -1.
        // rem_euclid(10) = 9 == d[9] OK; d11 = (sum10 = 50) % 10 = 0 == d[10] OK -> VALID.
        // This vector would fail validation with a plain `%` (regression lock).
        assert!(valid_tckn("19191919190"));
    }
}
