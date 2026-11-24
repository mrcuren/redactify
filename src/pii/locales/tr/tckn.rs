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
    // Repeated-digit values (`11111111110` ... `99999999990`) pass both
    // check digits and are deliberately NOT rejected: no official source
    // states that such numbers are never issued, and for a redactor masking
    // a dummy value is harmless while dropping a real one would leak it.
    d[9] == d10 && d[10] == d11
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// The contiguous 11 digits, or the dotted `232.475.469.02` (3-3-3-2; 20
/// values in piimask-eval-tr-en). The dotted form is
/// claimed cue-less like the contiguous one: the two check digits gate
/// both, and the grouping is no number format (a thousands separator
/// groups by three from the right). It is never cut out of a longer number
/// or an amount: no digit, dot or comma before it (the lookbehind after the
/// match) and no digit, or dot or comma plus digit, after it. Both forms
/// share one pattern: a separate rule would scan every line once more
/// (about 50 ms per 25 000 nm-kvkk/piimask lines with
/// fancy-regex 0.20), while the extra branch costs nothing measurable.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Tckn,
        r"(?<!\d)[1-9]\d{2}(?:\d{8}(?!\d)|\.\d{3}\.\d{3}\.\d{2}(?![\d]|[.,]\d)(?<![.,]\d{3}\.\d{3}\.\d{3}\.\d{2}))",
        Some(valid_grouped_tckn),
        ContextPolicy::None,
        1.0
    )
}

/// [`valid_tckn`] over the 11 digits of a candidate, contiguous or grouped
/// (one kind of separator, already enforced by the rule patterns).
fn valid_grouped_tckn(s: &str) -> bool {
    crate::pii::locales::code_chars::<11>(s, u8::is_ascii_digit, b". ")
        .is_some_and(|d| std::str::from_utf8(&d).is_ok_and(valid_tckn))
}

/// TCKN cue words (normalized form) for the cue-gated grouped shapes.
const CUES: &[&str] = &[
    "tc",
    "t.c.",
    "tckn",
    "kimlik",
    "vatandaslik",
    "vatandaşlik",
    "identity",
];

/// TCKN grouped with spaces (`275 395 931 48`, 3-3-3-2) or as a
/// thousands-grouped number (`17.291.716.060`, `17 291 716 060`, 2-3-3-3),
/// only next to a TCKN cue. In labelled fixtures, spaced 3-3-3-2 values
/// follow "kimlik", while the valid TCKN "172 917 160 60" also appears
/// without a cue as a plain number; a 2-3-3-3 group is how an 11-digit
/// amount is written, and about one amount in a hundred passes the two
/// check digits.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn thousands_rule() -> Rule {
    rule!(
        id = "tr::tckn_cued",
        EntityType::Tckn,
        r"(?<![\d.,])[1-9]\d(?:\.\d{3}\.\d{3}\.\d{3}| \d{3} \d{3} \d{3}|\d \d{3} \d{3} \d{2})(?![\d]|[.,]\d)",
        Some(valid_grouped_tckn),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_tckn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    fn tckns(text: &str) -> Vec<String> {
        engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::Tckn)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn grouped_forms_are_claimed_whole() {
        for (text, want) in [
            ("T.C. kimlik 232.475.469.02 şeklinde", "232.475.469.02"),
            ("Kimlik: 275 395 931 48", "275 395 931 48"),
            ("kimlik no 17 291 716 060 kayıtlı", "17 291 716 060"),
            ("TC kimlik 17.291.716.060 doğrulandı", "17.291.716.060"),
        ] {
            assert_eq!(tckns(text), [want], "{text}");
        }
    }

    #[test]
    fn grouped_forms_keep_their_guards() {
        // wrong check digits
        assert!(tckns("kimlik 232.475.469.03").is_empty());
        // the thousands shape without a cue is an amount
        assert!(tckns("toplam 17.291.716.060 TL").is_empty());
        assert!(tckns("toplam 17 291 716 060 TL").is_empty());
        // the spaced 3-3-3-2 shape without a cue is a plain number
        assert!(tckns("Sayı 172 917 160 60 boşluklu yazılmış").is_empty());
        // never cut out of a longer number or a mixed grouping
        assert!(tckns("1.232.475.469.02").is_empty());
        assert!(tckns("232.475.469.02.5").is_empty());
        assert!(tckns("232.475 469.02").is_empty());
    }

    #[test]
    fn long_hostile_lines_complete_within_the_backtrack_budget() {
        for r in [super::rule(), super::thousands_rule()] {
            for unit in ["1", "1.", "1 ", "12.", "123 ", "a"] {
                let text = unit.repeat(200_000 / unit.len());
                assert!(
                    r.regex.find_iter(&text).all(|m| m.is_ok()),
                    "{} on {unit:?}",
                    r.id
                );
            }
        }
    }

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
