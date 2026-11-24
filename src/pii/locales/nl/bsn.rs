//! Dutch BSN (burgerservicenummer): validator + rule.
//! Evidence: nl.wikipedia "Burgerservicenummer" (retrieved 2026-10-06):
//! 9 digits; elfproef `9·d1 + 8·d2 + … + 2·d8 − 1·d9 ≡ 0 (mod 11)` (the
//! last digit is weighted **−1** so Dutch bank account numbers cannot pass);
//! source-given valid examples: 123456782, 111222333.
//!
//! A cue is REQUIRED: ~9% of random 9-digit runs pass the elfproef
//! (VKN precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (i-normalized) that make a BSN candidate claimable.
pub(super) const CUES: &[&str] = &["bsn", "burgerservicenummer", "sofinummer", "persoonsnummer"];

/// Returns `true` if `bsn` is a valid Dutch BSN (9 digits passing the
/// elfproef with the −1 last-digit weight; a leading zero is significant,
/// so the input must already be 9 characters).
///
/// # Examples
/// ```
/// use redactify::valid_bsn;
/// assert!(valid_bsn("123456782"));  // source-given example
/// assert!(valid_bsn("111222333"));  // source-given example
/// assert!(!valid_bsn("123456789")); // weighted sum 165, not a multiple of 11
/// assert!(!valid_bsn("12345678"));  // 8 digits (leading-zero form is caller's job)
/// ```
#[must_use]
pub fn valid_bsn(bsn: &str) -> bool {
    let b = bsn.as_bytes();
    if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let d: [u32; 9] = std::array::from_fn(|i| u32::from(b[i] - b'0'));
    // weights 9,8,...,2 over digits 0..7, and -1 over the last digit
    let weighted: i64 = d
        .iter()
        .take(8)
        .enumerate()
        .map(|(i, &x)| i64::from(x) * i64::from(9 - i as u32))
        .sum::<i64>()
        - i64::from(d[8]);
    weighted % 11 == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Bsn,
        r"(?<!\d)\d{9}(?!\d)",
        Some(valid_bsn),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_bsn;

    #[test]
    fn elfproef_examples_from_source() {
        assert!(valid_bsn("123456782"));
        assert!(valid_bsn("111222333"));
        assert!(!valid_bsn("123456789"));
    }

    #[test]
    fn all_zero_is_algorithmically_valid() {
        // documented behavior: the pure elfproef accepts "000000000"
        // (weighted sum 0); the source gives no rule against it, so the
        // validator does not invent one. False positives stay bounded by
        // the RequiredCue gate ("bsn"-labeled all-zero text is synthetic).
        assert!(valid_bsn("000000000"));
    }
}
