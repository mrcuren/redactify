//! UK National Insurance number (NINO): validator + rule.
//!
//! Official source: HMRC internal manual "National Insurance Manual",
//! NIM39110 "National Insurance Numbers (NINOs): Format and Security: What
//! a NINO looks like" (updated 7 October 2026,
//! <https://www.gov.uk/hmrc-internal-manuals/national-insurance-manual/nim39110>,
//! retrieved 2026-10-30): "A NINO is made up of 2 letters, 6 numbers and a
//! final letter, which is always A, B, C, or D. It looks something like
//! this: QQ 12 34 56 A This is an example only and should not be used as
//! an actual number. [...] The characters D, F, I, Q, U, and V are not used
//! as either the first or second letter of a NINO prefix. The letter O is
//! not used as the second letter of a prefix. Prefixes BG, GB, KN, NK, NT,
//! TN and ZZ are not to be used". The manual states no check character.
//!
//! The validator applies the prefix rules above. Two recall choices go
//! beyond NIM39110: the suffix letter is optional
//! (the manual says a NINO always ends in A-D; the optional suffix follows
//! the electronic-submission convention quoted on `valid_nino`, for which
//! no official text is cited), and spaces between the pairs are tolerated
//! (the manual's own example is written in pairs).
//!
//! A cue is REQUIRED (no checksum - passport/VKN precedent).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue phrases that make a NINO candidate claimable (lowercase matching).
pub(super) const CUES: &[&str] = &[
    "nino",
    "national insurance",
    "ni number",
    "insurance number",
];

/// Returns `true` if `nino` is a structurally valid UK NINO (case
/// insensitive; internal single spaces tolerated; suffix letter optional
/// per the electronic-submission rule "may be a space if not known").
///
/// # Examples
/// ```
/// use redactify::valid_nino;
/// assert!(valid_nino("AB123456C"));
/// assert!(valid_nino("AB 12 34 56 c")); // spaced, lowercase, suffix
/// assert!(valid_nino("AB123456"));      // suffix omitted
/// assert!(!valid_nino("DQ123456C"));    // D invalid as first letter
/// assert!(!valid_nino("ZZ123456C"));    // unallocated combination
/// ```
#[must_use]
pub fn valid_nino(nino: &str) -> bool {
    let s: String = nino
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect();
    let b = s.as_bytes();
    // 8 chars (no suffix) or 9 (with suffix letter A-D)
    let core_len = if b.len() == 9 { 8 } else { b.len() };
    if core_len != 8 {
        return false;
    }
    if b.len() == 9 && !(b'A'..=b'D').contains(&b[8]) {
        return false;
    }
    let bad_first = |c: u8| matches!(c, b'D' | b'F' | b'I' | b'Q' | b'U' | b'V');
    let bad_second = |c: u8| bad_first(c) || c == b'O';
    if !b[0].is_ascii_uppercase()
        || !b[1].is_ascii_uppercase()
        || bad_first(b[0])
        || bad_second(b[1])
    {
        return false;
    }
    if !b[2..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    // prefixes "not to be used" (NIM39110)
    !matches!(
        (b[0], b[1]),
        (b'B', b'G')
            | (b'G', b'B')
            | (b'N', b'K')
            | (b'K', b'N')
            | (b'T', b'N')
            | (b'N', b'T')
            | (b'Z', b'Z')
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Nino,
        r"(?i)(?<![A-Za-z])[A-Z]{2}(?: ?\d{2}){3}(?: ?[A-D])?(?![A-Za-z0-9])",
        Some(valid_nino),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_nino;

    #[test]
    fn structural_rules() {
        assert!(valid_nino("AB123456C"));
        assert!(valid_nino("AB 12 34 56 C"));
        assert!(valid_nino("AB123456")); // suffix omitted (electronic form)
        assert!(!valid_nino("QQ123456")); // Q excluded; the classic textbook
                                          // "QQ123456C" example is explicitly flagged invalid by the source
        assert!(!valid_nino("AD123456C")); // D as second letter
        assert!(!valid_nino("AO123456C")); // O as second letter
        assert!(!valid_nino("BG123456C")); // unallocated combo
        assert!(!valid_nino("KN123456C"));
        assert!(!valid_nino("AB123456E")); // suffix range A-D
        assert!(!valid_nino("AB1234567")); // 7 digits
    }
}
