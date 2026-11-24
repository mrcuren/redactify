//! Australian Company Number (ACN): validator + detection rule.
//!
//! Official sources (ASIC, retrieved 2026-10-30):
//!
//! 1. "Australian Company Number digit check", section "How we validate
//!    Australian Company Numbers" (Internet Archive copy; the live URL now
//!    redirects to an ACN page without the algorithm)
//!    (<http://web.archive.org/web/20250424050753/https://asic.gov.au/for-business/registering-a-company/steps-to-register-a-company/australian-company-numbers/australian-company-number-digit-check>):
//!    "The Australian Company Number (ACN) is a nine digit number with the
//!    last digit being a check digit calculated using a modified modulus
//!    10 calculation. ASIC has adopted a convention of always printing and
//!    displaying the ACN in the format XXX XXX XXX [...] the inserted
//!    blanks do not form part of the ACN. [...] Step 1 - Apply weighting to
//!    digits 1 to 8 [weights 8 7 6 5 4 3 2 1] [...] Step 3 - Divide by 10
//!    to obtain remainder [...] Step 4 - Complement the remainder to 10
//!    [...] If the complement equals 10, set it to 0." Worked example:
//!    "ACN 004 085 616 is VALID"; all 44 further valid numbers listed on
//!    the page pass this validator.
//! 2. "Australian Company Number (ACN)", sections "What an ACN is" and
//!    "How to display your ACN"
//!    (<https://www.asic.gov.au/for-business-and-companies/companies/register-a-company/australian-company-number-acn>):
//!    "An ACN is a unique 9-digit number that identifies a company. [...]
//!    You may label an ACN as 'Australian Company Number', 'ACN' or
//!    'A.C.N.'" Its display example `123 456 789` fails the check digit;
//!    the validator follows the algorithm, not the illustration.
//!
//! The pattern takes the nine digits contiguous or in the ASIC `XXX XXX
//! XXX` grouping, and refuses to start or end next to a digit group, so
//! the last nine digits of a spaced ABN (`51 824 753 556`) are never an
//! ACN candidate.
//!
//! Cue REQUIRED (score 1.0, checksum verified): one check digit admits
//! about 10% of random 9-digit runs (measured). Cues are the ASIC labels:
//! "Australian Company Number" (a leading cue counts when its END lies
//! within the 18-character cue window before the value, see
//! `pii::context`, so the 25-character label is matched whole), "A.C.N.",
//! delimited "ACN" forms (a bare "acn" is a substring of "acne") and
//! "company number", which also covers the label's shorter variants.

use crate::pii::entity::EntityType;
use crate::pii::locales::{code_chars, rule, ContextPolicy, Rule};

/// Cue words that make an ACN candidate claimable.
pub(super) const CUES: &[&str] = &[
    "australian company number",
    "acn:",
    "acn#",
    "acn ",
    "(acn)",
    "a.c.n",
    "company number",
];

/// Returns `true` if `s` is a valid Australian Company Number: nine ASCII
/// digits, contiguous or grouped `XXX XXX XXX`, whose ninth digit is the
/// ASIC check digit (weights 8 to 1 over the first eight digits, the
/// remainder mod 10 complemented to 10, 10 read as 0).
///
/// # Examples
/// ```
/// use redactify::valid_au_acn;
/// assert!(valid_au_acn("004 085 616")); // ASIC worked example
/// assert!(valid_au_acn("004085616"));
/// assert!(!valid_au_acn("004 085 617")); // check digit off
/// assert!(!valid_au_acn("123 456 789")); // ASIC display illustration
/// ```
#[must_use]
pub fn valid_au_acn(s: &str) -> bool {
    let b = s.as_bytes();
    let grouped = b.len() == 11 && b[3] == b' ' && b[7] == b' ';
    if !(b.len() == 9 || grouped) {
        return false;
    }
    let Some(d) = code_chars::<9>(s, u8::is_ascii_digit, b" ") else {
        return false;
    };
    let sum: u32 = d[..8]
        .iter()
        .zip((1..=8u32).rev())
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    (10 - sum % 10) % 10 == u32::from(d[8] - b'0')
}

/// The pattern consumes the first digit before its two lookbehinds (no
/// digit, and no "digit + space", ahead of it), so every start position
/// fails in one backtracking step and a very long line stays within the
/// engine's backtrack budget (two leading lookbehinds measurably exhausted
/// it on a 400,000-mark combining run).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::AuAcn,
        r"\d(?<!\d\d)(?<!\d \d)\d{2} ?\d{3} ?\d{3}(?!\d)(?! \d)",
        Some(valid_au_acn),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_au_acn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn official_vectors_and_edges() {
        for v in ["004 085 616", "000 000 019", "000 250 000", "010 749 961"] {
            assert!(valid_au_acn(v), "{v}");
        }
        assert!(!valid_au_acn("004 085 617"));
        assert!(!valid_au_acn("000 000 018"));
        assert!(!valid_au_acn("123 456 789"));
        assert!(!valid_au_acn("004-085-616")); // ASIC prints blanks only
        assert!(!valid_au_acn("004 085616")); // only the 3-3-3 grouping
        assert!(!valid_au_acn("00408561")); // 8 digits
        assert!(!valid_au_acn(""));
        // ASIC worked example: 0*8 + 0*7 + 4*6 + 0*5 + 8*4 + 5*3 + 6*2 +
        // 1*1 = 84, remainder 4, complement 6 = the ninth digit
        assert_eq!(4 * 6 + 8 * 4 + 5 * 3 + 6 * 2 + 1, 84);
    }

    #[test]
    fn cue_required_and_spaced_abn_untouched() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["au"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(kinds("ACN 004 085 616"), vec![EntityType::AuAcn]);
        assert_eq!(kinds("A.C.N. 004085616"), vec![EntityType::AuAcn]);
        assert_eq!(
            kinds("Australian Company Number: 004 085 616"),
            vec![EntityType::AuAcn]
        );
        assert!(kinds("order 004 085 616 shipped").is_empty());
        assert!(kinds("acne 004 085 616").is_empty());
        // a spaced ABN stays an ABN (its last nine digits are no ACN)
        assert_eq!(kinds("ABN 51 824 753 556"), vec![EntityType::AuAbn]);
    }
}
