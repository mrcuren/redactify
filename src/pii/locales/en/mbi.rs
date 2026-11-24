//! US Medicare Beneficiary Identifier (MBI): validator + detection rule.
//!
//! Official source (retrieved 2026-10-31): CMS, "Understanding the Medicare
//! Beneficiary Identifier (MBI) Format", sections "MBI Format" and "Where
//! will the MBI's characters go?"
//! (<https://www.cms.gov/medicare/new-medicare-card/understanding-the-mbi.pdf>):
//! "The MBI has 11 characters [...] We'll use numbers 0-9 and all letters
//! from A to Z, except for S, L, O, I, B, and Z. [...] Here's an example:
//! 1EG4-TE5-MK73 [...] The dashes aren't used as part of the MBI." The
//! position table reads `C A AN N A AN N A A N N`, with "C - Numeric 1 thru
//! 9", "N - Numeric 0 thru 9", "A - Alphabetic Character (A...Z);
//! Excluding (S, L, O, I, B, Z)" and "AN - Either A or N".
//!
//! Accepted spellings: the 11 characters contiguous, or with the two
//! dashes of the card example (after the 4th and the 7th character).
//! Uppercase only: the source states that its system converts lowercase
//! letters, which is input handling, not the printed form.
//!
//! Format only: the source defines no check character, so a cue is
//! REQUIRED and the score is 0.9. A bare "mbi" is not a cue (substring of
//! "combine", "ambition", "zombie"); the delimited label forms and
//! "medicare" are.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make an MBI candidate claimable.
pub(super) const CUES: &[&str] = &["mbi:", "mbi#", "mbi ", " mbi", "(mbi)", "medicare"];

/// The CMS position table: `C` numeric 1-9, `N` numeric 0-9, `A` an
/// allowed letter, `X` either an allowed letter or a digit ("AN").
const POSITIONS: &[u8; 11] = b"CAXNAXNAANN";

/// An MBI letter: `A`-`Z` except `S`, `L`, `O`, `I`, `B` and `Z`.
fn mbi_letter(b: u8) -> bool {
    b.is_ascii_uppercase() && !b"SLOIBZ".contains(&b)
}

/// Returns `true` if `s` has the CMS Medicare Beneficiary Identifier
/// format: 11 characters `C A AN N A AN N A A N N` (letters exclude `S`,
/// `L`, `O`, `I`, `B`, `Z`), contiguous or dashed as `XXXX-XXX-XXXX`.
///
/// # Examples
/// ```
/// use redactify::valid_us_mbi;
/// assert!(valid_us_mbi("1EG4-TE5-MK73")); // CMS example
/// assert!(valid_us_mbi("1EG4TE5MK73"));
/// assert!(!valid_us_mbi("0EG4TE5MK73")); // position 1 is 1-9
/// assert!(!valid_us_mbi("1SG4TE5MK73")); // S is never used
/// ```
#[must_use]
pub fn valid_us_mbi(s: &str) -> bool {
    let b = s.as_bytes();
    let code: [u8; 11] = match b.len() {
        11 => {
            let mut c = [0u8; 11];
            c.copy_from_slice(b);
            c
        }
        13 if b[4] == b'-' && b[8] == b'-' => {
            let mut c = [0u8; 11];
            c[..4].copy_from_slice(&b[..4]);
            c[4..7].copy_from_slice(&b[5..8]);
            c[7..].copy_from_slice(&b[9..]);
            c
        }
        _ => return false,
    };
    code.iter().zip(POSITIONS).all(|(&c, &kind)| match kind {
        b'C' => matches!(c, b'1'..=b'9'),
        b'N' => c.is_ascii_digit(),
        b'A' => mbi_letter(c),
        _ => c.is_ascii_digit() || mbi_letter(c),
    })
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsMbi,
        r"(?<![A-Za-z0-9])[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y][0-9]-?[AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y][0-9]-?[AC-HJKMNP-RT-Y]{2}[0-9]{2}(?![A-Za-z0-9])",
        Some(valid_us_mbi),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{mbi_letter, valid_us_mbi};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn official_example_and_position_edges() {
        assert!(valid_us_mbi("1EG4-TE5-MK73"));
        assert!(valid_us_mbi("1EG4TE5MK73"));
        assert!(!valid_us_mbi("0EG4TE5MK73")); // position 1 = 0
        assert!(!valid_us_mbi("1SG4TE5MK73")); // excluded letter S
        assert!(!valid_us_mbi("1EG4TE5MK7A")); // position 11 is numeric
        assert!(!valid_us_mbi("1EG4-TE5MK73")); // a single dash
        assert!(!valid_us_mbi("1EG-4TE5-MK73")); // dashes off the card positions
        assert!(!valid_us_mbi("1eg4te5mk73")); // lowercase
        assert!(!valid_us_mbi("1EG4TE5MK733")); // 12 characters
        assert!(!valid_us_mbi(""));
        // the AN positions take either kind
        assert!(valid_us_mbi("1E04T05MK73"));
        // exactly 20 letters are allowed
        assert_eq!((b'A'..=b'Z').filter(|&c| mbi_letter(c)).count(), 20);
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["en"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(kinds("MBI: 1EG4-TE5-MK73"), vec![EntityType::UsMbi]);
        assert_eq!(
            kinds("Medicare number 1EG4TE5MK73"),
            vec![EntityType::UsMbi]
        );
        assert!(kinds("part 1EG4TE5MK73 shipped").is_empty());
        assert!(kinds("combine 1EG4TE5MK73").is_empty());
    }
}
