//! Turkish tax number (VKN): validator + detection rule (checksum + mandatory cue).

/// Returns `true` if `vkn` is a valid VKN.
///
/// Rules: exactly 10 ASCII digits; a weighted sum is computed from the first
/// 9 digits (`(d[i] + 9 - i) mod 10`; contribute 9 when `tmp == 9`, otherwise
/// `tmp * 2^(9-i) mod 9`), and `10 - (sum mod 10) mod 10` must equal the last
/// digit.
///
/// **Structural weakness:** a single check digit lets roughly 10% of random
/// 10-digit strings pass. Therefore [`crate::detect`] only accepts a bare VKN
/// candidate when a `vergi`/`VKN` cue appears nearby.
///
/// # Examples
/// ```
/// use redactify::valid_vkn;
/// assert!(valid_vkn("1234567890"));
/// assert!(!valid_vkn("1234567891"));
/// assert!(!valid_vkn("123456789")); // 9 digits
/// ```
#[must_use]
pub fn valid_vkn(vkn: &str) -> bool {
    let bytes = vkn.as_bytes();
    if bytes.len() != 10 || !bytes.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let d: [u32; 10] = std::array::from_fn(|i| u32::from(bytes[i] - b'0'));
    let mut total: u32 = 0;
    for (i, &di) in d.iter().enumerate().take(9) {
        let tmp = (di + 9 - i as u32) % 10;
        total += if tmp == 9 {
            9
        } else {
            (tmp * 2u32.pow(9 - i as u32)) % 9
        };
    }
    (10 - total % 10) % 10 == d[9]
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a bare 10-digit candidate claimable as a VKN.
pub(super) const CUES: &[&str] = &["vkn", "v.k.n", "vergi", "tax"];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Vkn,
        r"(?<!\d)\d{10}(?!\d)",
        Some(valid_vkn),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_vkn;

    #[test]
    fn golden_vectors() {
        assert!(valid_vkn("1234567890"));
        assert!(valid_vkn("3949583520"));
        assert!(valid_vkn("5726881770"));
        assert!(valid_vkn("9365878344"));
        assert!(!valid_vkn("1234567891"));
        assert!(!valid_vkn("123456789")); // 9 digits
        assert!(!valid_vkn("12345678901")); // 11 digits
        assert!(!valid_vkn("123456789a"));
        assert!(!valid_vkn(""));
    }
}
